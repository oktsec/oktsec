package gateway

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/identity/resolve"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// echoBackends is the single-server backend map used by the audit
// identity tests. The echo server is defined in gateway_test.go and
// exposes one tool ("echo") with a permissive schema.
func echoBackends() map[string]*mcp.Server {
	return map[string]*mcp.Server{"echo": echoServer()}
}

// ctxWithIdentity builds a request context shaped exactly like the auth
// middleware leaves it after a successful Resolve. Tests use this to
// drive makeHandler() without spinning up the full HTTP path — the
// middleware contract is already covered in identity_test.go.
func ctxWithIdentity(principal, authMethod, trustLevel, reportedActor string) context.Context {
	ctx := context.Background()
	if principal != "" {
		ctx = context.WithValue(ctx, agentContextKey, principal)
	}
	if authMethod != "" {
		ctx = context.WithValue(ctx, authMethodContextKey, authMethod)
	}
	if trustLevel != "" {
		ctx = context.WithValue(ctx, trustLevelContextKey, trustLevel)
	}
	if reportedActor != "" {
		ctx = context.WithValue(ctx, reportedActorContextKey, reportedActor)
	}
	return ctx
}

// lastAuditEntry returns the most recently inserted entry for a given
// principal id. Tests call gw.audit.Flush() first to drain the batch
// writer.
func lastAuditEntry(t *testing.T, gw *Gateway, principal string) audit.Entry {
	t.Helper()
	gw.audit.Flush()
	entries, err := gw.audit.Query(audit.QueryOpts{Agent: principal, Limit: 1})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "no audit entry for principal %q", principal)
	return entries[0]
}

// 1. Bearer principal + spoofed reported actor: audit row stores
// FromAgent=principal (the bearer-token owner) while ReportedActor
// carries the spoofed display name. AuthMethod records bearer_token so
// downstream readers can tell HOW it was authenticated.
func TestAudit_BearerPrincipalSeparatesReportedActor(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["local-codex"] = config.Agent{}
	gw := newTestGateway(t, cfg, echoBackends())

	ctx := ctxWithIdentity(
		"local-codex",                            // principal
		string(resolve.AuthMethodBearerToken),    // auth method
		string(resolve.TrustAuthenticated),       // trust level
		"admin",                                  // spoofed reported actor
	)
	handler := gw.makeHandler(gw.toolMap["echo"])
	_, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"}))
	require.NoError(t, err)

	e := lastAuditEntry(t, gw, "local-codex")
	assert.Equal(t, "local-codex", e.FromAgent, "policy principal must be from bearer, not spoofed actor")
	assert.Equal(t, string(resolve.AuthMethodBearerToken), e.AuthMethod)
	assert.Equal(t, string(resolve.TrustAuthenticated), e.PrincipalTrustLevel)
	assert.Equal(t, "admin", e.ReportedActor, "reported actor preserved for display")
}

// 2. Local legacy loopback header: principal name comes from the header,
// auth method records trusted_loopback so readers can distinguish it
// from token-authenticated rows. ReportedActor stays empty when no
// surface header / payload supplied one.
func TestAudit_LocalLegacyLoopbackHeader(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["claude-code"] = config.Agent{}
	gw := newTestGateway(t, cfg, echoBackends())

	ctx := ctxWithIdentity(
		"claude-code",
		string(resolve.AuthMethodTrustedLoopback),
		string(resolve.TrustLocal),
		"", // no reported actor
	)
	handler := gw.makeHandler(gw.toolMap["echo"])
	_, err := handler(ctx, makeHandlerRequest("echo", map[string]any{"text": "hi"}))
	require.NoError(t, err)

	e := lastAuditEntry(t, gw, "claude-code")
	assert.Equal(t, "claude-code", e.FromAgent)
	assert.Equal(t, string(resolve.AuthMethodTrustedLoopback), e.AuthMethod)
	assert.Equal(t, string(resolve.TrustLocal), e.PrincipalTrustLevel)
	assert.Empty(t, e.ReportedActor, "no reported actor source means empty field")
}

// 3. The _oktsec_agent payload param surfaces as ReportedActor but never
// becomes the policy Principal. This is the structural invariant: the
// payload supplies display metadata, the bearer token / loopback header
// supplies authority.
func TestAudit_OktsecAgentPayloadDoesNotChangeFromAgent(t *testing.T) {
	cfg := defaultGatewayConfig()
	cfg.Agents["local-codex"] = config.Agent{}
	gw := newTestGateway(t, cfg, echoBackends())

	ctx := ctxWithIdentity(
		"local-codex",
		string(resolve.AuthMethodBearerToken),
		string(resolve.TrustAuthenticated),
		"", // no header reported actor
	)
	handler := gw.makeHandler(gw.toolMap["echo"])
	_, err := handler(ctx, makeHandlerRequest("echo", map[string]any{
		"text":          "hi",
		"_oktsec_agent": "review-subagent", // payload sub-agent
	}))
	require.NoError(t, err)

	e := lastAuditEntry(t, gw, "local-codex")
	assert.Equal(t, "local-codex", e.FromAgent, "principal must come from auth, not payload")
	assert.Equal(t, "review-subagent", e.ReportedActor, "payload sub-agent surfaces as reported actor")
	assert.Equal(t, string(resolve.AuthMethodBearerToken), e.AuthMethod)
}

// 4. Backward compatibility: an Entry written without identity provenance
// fields persists and reads back as empty strings. This guards the
// migration: existing audit rows from before #61 must keep working.
func TestAudit_BackwardCompatEmptyIdentityFields(t *testing.T) {
	cfg := defaultGatewayConfig()
	gw := newTestGateway(t, cfg, echoBackends())

	// Old-style entry with no identity provenance.
	gw.audit.Log(audit.Entry{
		ID:             "legacy-1",
		Timestamp:      "2026-04-01T00:00:00Z",
		FromAgent:      "legacy-agent",
		ToAgent:        "legacy-agent",
		Status:         audit.StatusDelivered,
		PolicyDecision: "ok",
	})
	gw.audit.Flush()

	e, err := gw.audit.QueryByID("legacy-1")
	require.NoError(t, err)
	require.NotNil(t, e, "legacy entry should be retrievable")
	assert.Equal(t, "legacy-agent", e.FromAgent)
	assert.Empty(t, e.AuthMethod, "old rows have no auth_method")
	assert.Empty(t, e.PrincipalTrustLevel, "old rows have no trust_level")
	assert.Empty(t, e.ReportedActor, "old rows have no reported_actor")
}
