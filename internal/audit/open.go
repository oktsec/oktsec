package audit

import (
	"database/sql"
	"fmt"
	"log/slog"

	// Register pgx as database/sql driver for Postgres connections.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Open creates an audit store based on the backend type.
// Supported backends: "sqlite" (default), "postgres".
//
// For SQLite, dsn is the file path (e.g., "~/.oktsec/oktsec.db").
// For Postgres, dsn is the connection string (e.g., "postgres://user:pass@host/db").
func Open(backend, dsn string, logger *slog.Logger, retentionDays int) (*Store, error) {
	switch backend {
	case "", "sqlite":
		return NewStore(dsn, logger, retentionDays)

	case "postgres", "postgresql":
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, fmt.Errorf("opening postgres: %w", err)
		}
		// Verify connectivity
		if err := db.Ping(); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("connecting to postgres: %w", err)
		}
		return NewStoreWithDB(db, PostgresDialect{}, logger, retentionDays)

	default:
		return nil, fmt.Errorf("unsupported db_backend %q (supported: sqlite, postgres)", backend)
	}
}
