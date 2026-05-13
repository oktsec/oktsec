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
	return nil
}

// IsValidPrincipalName is the boolean predicate form of
// ValidatePrincipalName. Use it when filtering filesystem entries where
// a returned error would be noise (for example when enumerating .pub
// files and silently skipping invalid filenames).
func IsValidPrincipalName(name string) bool {
	return ValidatePrincipalName(name) == nil
}
