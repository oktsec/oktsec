package verdict

import "github.com/oktsec/oktsec/internal/engine"

// EscalateOneLevel bumps a verdict one severity level:
// clean → flag, flag → quarantine, quarantine → block.
// Block remains block (already at maximum).
//
// This is a pure function with no side effects, suitable for use by both
// the proxy handler and the gateway security pipeline.
func EscalateOneLevel(v engine.ScanVerdict) engine.ScanVerdict {
	switch v {
	case engine.VerdictClean:
		return engine.VerdictFlag
	case engine.VerdictFlag:
		return engine.VerdictQuarantine
	case engine.VerdictQuarantine:
		return engine.VerdictBlock
	default:
		return v // block stays block
	}
}
