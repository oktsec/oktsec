package hooks

import (
	"log/slog"
	"testing"

	"github.com/oktsec/oktsec/internal/audit"
)

func mustCreateAuditStore(t *testing.T, dbPath string, logger *slog.Logger) *audit.Store {
	t.Helper()
	store, err := audit.NewStore(dbPath, logger, 90)
	if err != nil {
		t.Fatalf("creating audit store: %v", err)
	}
	return store
}
