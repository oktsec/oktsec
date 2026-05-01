package policy

import "github.com/oktsec/oktsec/internal/config"

// DefaultMaxDelegationDepth is the cap applied when the agent has
// no per-agent override. The number is intentionally
// conservative: a delegation chain is the trust path that backs
// every authorization decision under this header, and a
// runaway depth makes that path harder to audit. Operators who
// genuinely need more can override per-agent or pass <0 for
// unlimited.
const DefaultMaxDelegationDepth = 3

// ResolveDelegationDepth picks the effective delegation-depth
// cap for an agent. The proxy and gateway both consume this
// helper so the cap stays consistent across the two surfaces.
//
// Semantics:
//   - per-agent MaxDelegationDepth < 0  → unlimited (returns -1).
//   - per-agent MaxDelegationDepth > 0  → that exact cap.
//   - per-agent MaxDelegationDepth == 0 → fall through to default.
//   - agent unknown                     → default.
//   - cfg == nil                        → default.
//
// "Depth" is the number of hops in the delegation chain (chain
// length): a single token chain `root -> delegate` has depth 1;
// `root -> a -> b` has depth 2. A cap of 1 therefore allows the
// single-hop chain and blocks the two-hop one.
func ResolveDelegationDepth(cfg *config.Config, agent string) int {
	if cfg == nil {
		return DefaultMaxDelegationDepth
	}
	if ac, ok := cfg.Agents[agent]; ok {
		switch {
		case ac.MaxDelegationDepth < 0:
			return -1
		case ac.MaxDelegationDepth > 0:
			return ac.MaxDelegationDepth
		}
	}
	return DefaultMaxDelegationDepth
}
