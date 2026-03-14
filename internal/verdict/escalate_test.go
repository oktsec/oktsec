package verdict

import (
	"testing"

	"github.com/oktsec/oktsec/internal/engine"
)

func TestEscalateOneLevel(t *testing.T) {
	tests := []struct {
		input engine.ScanVerdict
		want  engine.ScanVerdict
	}{
		{engine.VerdictClean, engine.VerdictFlag},
		{engine.VerdictFlag, engine.VerdictQuarantine},
		{engine.VerdictQuarantine, engine.VerdictBlock},
		{engine.VerdictBlock, engine.VerdictBlock}, // already max
	}

	for _, tt := range tests {
		got := EscalateOneLevel(tt.input)
		if got != tt.want {
			t.Errorf("EscalateOneLevel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEscalateOneLevel_IsPure(t *testing.T) {
	// Calling EscalateOneLevel should not modify any external state
	v1 := EscalateOneLevel(engine.VerdictClean)
	v2 := EscalateOneLevel(engine.VerdictClean)
	if v1 != v2 {
		t.Errorf("EscalateOneLevel is not pure: %q != %q", v1, v2)
	}
}
