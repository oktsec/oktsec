// Package resolve centralizes principal/reported-actor identity resolution
// for surface adapters (gateway, hooks, forward proxy, agent message API).
//
// Surface adapters do not invent principal semantics on their own. They
// gather Evidence from the request and call a Resolver, which returns a
// Principal (used for policy decisions) and an optional ReportedActor
// (display/audit metadata supplied by the surface or its payload).
//
// The Principal is the only identity policy code may use for ACL,
// suspension, rate limit, constraints, delegation enforcement, or blocking.
// The ReportedActor never overrides the Principal.
package resolve

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
)

// AuthMethod names how the Principal was established.
type AuthMethod string

const (
	AuthMethodNone            AuthMethod = ""
	AuthMethodEd25519         AuthMethod = "ed25519"
	AuthMethodBearerToken     AuthMethod = "bearer_token"
	AuthMethodProxyToken      AuthMethod = "proxy_token"
	AuthMethodMTLS            AuthMethod = "mtls"
	AuthMethodWrapper         AuthMethod = "wrapper"
	AuthMethodTrustedLoopback AuthMethod = "trusted_loopback"
	AuthMethodHookToken       AuthMethod = "hook_token"
)

// TrustLevel describes how strongly the Principal is established. Policy
// gates may require a minimum TrustLevel before allowing a class of action.
type TrustLevel string

const (
	TrustAuthenticated TrustLevel = "authenticated" // token, signature, mTLS verified
	TrustLocal         TrustLevel = "trusted_local" // loopback header / wrapper / config ownership in local profile
	TrustObserved      TrustLevel = "observed"      // unauthenticated telemetry
	TrustInferred      TrustLevel = "inferred"      // correlation only
	TrustAnonymous     TrustLevel = "anonymous"     // no identity established
)

// trustOrder defines the ordering for MeetsMinimumTrust comparisons.
// Higher values indicate stronger evidence; gates compare with `>=`.
var trustOrder = map[TrustLevel]int{
	TrustAnonymous:     0,
	TrustObserved:      1,
	TrustInferred:      2,
	TrustLocal:         3,
	TrustAuthenticated: 4,
}

// trustRank returns the comparable rank for a TrustLevel, defaulting to
// 0 (anonymous) for unknown values so policy gates fail closed on typos.
func trustRank(t TrustLevel) int {
	r, ok := trustOrder[t]
	if !ok {
		return 0
	}
	return r
}

// PrincipalKind classifies the Principal entity. Useful for policy and UI.
type PrincipalKind string

const (
	PrincipalKindAgent     PrincipalKind = "agent"
	PrincipalKindUser      PrincipalKind = "user"
	PrincipalKindService   PrincipalKind = "service"
	PrincipalKindWorkspace PrincipalKind = "workspace"
	PrincipalKindUnknown   PrincipalKind = "unknown"
)

// Surface names the technical boundary that gathered the Evidence. Each
// surface has its own coverage and identity expectations.
type Surface string

const (
	SurfaceMCPHTTP      Surface = "mcp_http"
	SurfaceMCPStdio     Surface = "mcp_stdio"
	SurfaceHTTPEgress   Surface = "http_egress_proxy"
	SurfaceHooks        Surface = "hooks"
	SurfaceAgentMessage Surface = "agent_message_api"
	SurfaceFilesystem   Surface = "filesystem_guard"
	SurfaceActivityLog  Surface = "activity_log"
)

// Evidence is everything a surface adapter has observed about a request.
// The Resolver is responsible for combining these signals into a Principal
// and (optionally) a ReportedActor. Adapters must not pre-decide.
type Evidence struct {
	Surface     Surface
	Header      http.Header
	RemoteAddr  string             // raw RemoteAddr; resolver decides if loopback
	TLSPeer     *x509.Certificate  // nil unless mTLS handshake completed
	Payload     map[string]any     // surface-supplied parsed payload (e.g. hook body, JSON-RPC params)
	LocalSource string             // for stdio wrapper: the wrapper config that started the process
	ConfigAgent string             // legacy: agent name from request context (e.g. X-Oktsec-Agent)
}

// Principal is the authenticated security identity used for all policy
// decisions. It must come from one of the AuthMethods declared in config
// for the originating Surface. Payload-supplied fields cannot create one.
type Principal struct {
	ID          string
	DisplayName string
	Kind        PrincipalKind
	AuthMethod  AuthMethod
	TrustLevel  TrustLevel
	TokenID     string // empty when auth method is not token-based
	WorkspaceID string
	// Context is provider-neutral identity enrichment. Empty is valid
	// and means no external identity context is configured. It is
	// metadata only — authorization stays driven by ID, AuthMethod,
	// TrustLevel, delegation, suspension, ACL, and runtime policy.
	Context PrincipalContext
}

// PrincipalContext is the provider-neutral identity context model.
// Phase 4E-0 wires it as static enrichment carried through config; a
// later phase may populate it from verified OIDC/JWT claims, but no
// code path may branch on Provider — it is display metadata only.
type PrincipalContext struct {
	Issuer     string
	Subject    string
	Audience   string
	ClientID   string
	TenantID   string
	Groups     []string
	Scopes     []string
	Provider   string // display-only label, e.g. "custom_oidc"
	Source     string // "static_config" in 4E-0; "oidc_jwt" reserved for 4E-1
	Verified   bool
	ExpiresAt  string
	ClaimsHash string // optional short hash if raw claims existed upstream
}

// IsZero reports whether the context carries no enrichment. Used by
// the posture builder and by tests to decide whether to render the
// "external context mapped" copy or the local-only fallback.
func (c PrincipalContext) IsZero() bool {
	return c.Issuer == "" && c.Subject == "" && c.Audience == "" &&
		c.ClientID == "" && c.TenantID == "" && c.Provider == "" &&
		c.Source == "" && c.ExpiresAt == "" && c.ClaimsHash == "" &&
		!c.Verified && len(c.Groups) == 0 && len(c.Scopes) == 0
}

// ReportedActor is display/audit metadata supplied by the surface (header,
// payload, hook body) or inferred by correlation. It is rendered in the UI
// alongside the Principal, but never used for policy.
type ReportedActor struct {
	ID          string
	DisplayName string
	Source      string // header, payload, hook, log, inference
	Confidence  string // high, medium, low
}

// Result is what the Resolver returns to a surface adapter.
type Result struct {
	Principal     Principal
	ReportedActor ReportedActor
	Warnings      []string // non-fatal advisories the surface may want to log/audit
}

// MeetsMinimumTrust reports whether the resolved Principal carries at
// least the requested TrustLevel. Use this to gate fail-closed paths in
// surface adapters (e.g. enterprise gateway requiring TrustAuthenticated).
func (r Result) MeetsMinimumTrust(min TrustLevel) bool {
	return trustRank(r.Principal.TrustLevel) >= trustRank(min)
}

// RequireMinimumTrust returns ErrInsufficientTrust when the resolved
// Principal does not meet `min`. Surface adapters in fail-closed mode call
// this immediately after Resolve and short-circuit the request on error.
func (r Result) RequireMinimumTrust(min TrustLevel) error {
	if r.MeetsMinimumTrust(min) {
		return nil
	}
	return &InsufficientTrustError{
		Required: min,
		Got:      r.Principal.TrustLevel,
		Method:   r.Principal.AuthMethod,
	}
}

// InsufficientTrustError is returned by RequireMinimumTrust. Surfaces can
// inspect Required/Got/Method to choose an appropriate failure mode (HTTP
// 401 with WWW-Authenticate hint, JSON-RPC error, etc.).
type InsufficientTrustError struct {
	Required TrustLevel
	Got      TrustLevel
	Method   AuthMethod
}

func (e *InsufficientTrustError) Error() string {
	return "identity: trust level " + string(e.Got) +
		" (auth=" + string(e.Method) + ") does not meet required " + string(e.Required)
}

// Resolver turns Evidence into a (Principal, ReportedActor) for a given
// surface configuration. Implementations must be safe for concurrent use.
//
// The Config argument is mandatory because identity rules differ per
// surface: the gateway accepts gateway bearer tokens and (optionally) the
// loopback header, the egress proxy accepts proxy basic tokens, and so on.
// A surface adapter that does not pass its Config will get the wrong rules.
type Resolver interface {
	Resolve(ctx context.Context, cfg Config, evidence Evidence) (Result, error)
}

// IsLoopback reports whether a raw RemoteAddr originates from the loopback
// interface. Only the literal IPv4/IPv6 loopback addresses are accepted;
// the DNS name "localhost" is rejected because it can be poisoned at the
// system level.
func IsLoopback(remoteAddr string) bool {
	if remoteAddr == "" {
		return false
	}
	// SplitHostPort handles "ip:port", "[ipv6]:port", and rejects bare
	// IPv6 (e.g. "::1") with an error — fall back to ParseIP for those.
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}
