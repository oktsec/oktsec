package identity

import (
	"fmt"
	"regexp"
	"strings"
)

// principalNameRE is the canonical principal name shape: must start
// with a letter, digit, or underscore, then up to 127 of
// [A-Za-z0-9._-]. Total length is bounded at 128 characters.
//
// Leading underscore is allowed for the small set of internal reserved
// principals such as _proxy (used for audit-chain signing). Leading dot
// is still rejected because it would create hidden files on Unix and
// confuse directory enumeration.
var principalNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

// MaxPrincipalNameLen is the maximum length accepted by
// ValidatePrincipalName. 128 leaves room for sensible agent names while
// staying well under PATH_MAX on every supported platform.
const MaxPrincipalNameLen = 128

// windowsReservedNames is the set of basenames that map to character
// devices on Windows regardless of file extension. Writing to
// "NUL.key" on Windows opens the null device, so the validator must
// refuse these basenames case-insensitively on every platform — the
// resulting config files are shared across darwin, linux, and windows
// hosts.
//
// Source: Microsoft "Naming Files, Paths, and Namespaces" doc, "DOS
// device names" section.
var windowsReservedNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {}, "com5": {},
	"com6": {}, "com7": {}, "com8": {}, "com9": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
}

// ValidatePrincipalName returns nil if name is safe to use as the basis
// of a key filename or agent identifier. Otherwise it returns an
// actionable error describing the violation.
//
// Callers MUST NOT silently rewrite a rejected name into a different
// "safe" name. Rewriting would let two distinct upstream identities
// collide on a single ACL and audit row, which is worse than refusing
// the operation.
//
// Allowed: ^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$
//
//	filesystem, github, research-agent, agent_01, org.tool, _proxy
//
// Rejected: empty, ".", "..", anything containing path separators
// (/, \), NUL bytes, leading ".", leading "-", characters outside
// [A-Za-z0-9._-], longer than 128 characters.
func ValidatePrincipalName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid principal name: name is empty")
	}
	if len(name) > MaxPrincipalNameLen {
		return fmt.Errorf("invalid principal name %q: length %d exceeds %d", name, len(name), MaxPrincipalNameLen)
	}
	// Explicit checks for the highest-impact cases produce clearer
	// errors than a single regex mismatch message.
	if strings.IndexByte(name, 0) >= 0 {
		return fmt.Errorf("invalid principal name %q: contains a NUL byte", name)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid principal name %q: contains a path separator", name)
	}
	if !principalNameRE.MatchString(name) {
		return fmt.Errorf("invalid principal name %q: must start with a letter, digit, or underscore and contain only letters, digits, dot, underscore, or dash", name)
	}
	// Windows device-name check applies to the basename before the
	// extension. Strip a trailing ".x...x" segment (the part after
	// the first dot) and look up the lowercased prefix.
	stem := name
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		stem = name[:dot]
	}
	if _, reserved := windowsReservedNames[strings.ToLower(stem)]; reserved {
		return fmt.Errorf("invalid principal name %q: %s is a reserved Windows device name", name, stem)
	}
	return nil
}

// IsValidPrincipalName is the boolean predicate form of
// ValidatePrincipalName. Use it when filtering filesystem entries where
// a returned error would be noise (for example when enumerating .pub
// files and silently skipping invalid filenames).
func IsValidPrincipalName(name string) bool {
	return ValidatePrincipalName(name) == nil
}

// IsReservedPrincipalName reports whether name is reserved for
// internal use. Anything starting with "_" is reserved by convention.
// The signing principal _proxy is the only current consumer, but new
// internal principals follow the same prefix.
//
// Public surfaces (HTTP APIs, dashboard forms, CLI arguments, config
// load, SDK callers) MUST reject reserved names so an external caller
// cannot overwrite an internal key file. Only the identity package
// and the audit-chain bootstrap may consume reserved names.
func IsReservedPrincipalName(name string) bool {
	return len(name) > 0 && name[0] == '_'
}

// ValidatePublicPrincipalName is the validator every user-facing
// surface should call. It enforces the same filesystem-safety contract
// as ValidatePrincipalName and additionally refuses internal reserved
// names so an external caller cannot collide with a signing identity
// such as _proxy.
func ValidatePublicPrincipalName(name string) error {
	if err := ValidatePrincipalName(name); err != nil {
		return err
	}
	if IsReservedPrincipalName(name) {
		return fmt.Errorf("principal name %q is reserved for internal use", name)
	}
	return nil
}
