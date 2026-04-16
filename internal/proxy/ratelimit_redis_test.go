package proxy

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisStore(t *testing.T, limit int, window time.Duration) (*RedisRateStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := NewRedisRateStore(client, limit, window, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Stop)
	return store, mr
}

func TestRedisRateStore_AllowsUpToLimit(t *testing.T) {
	store, _ := newTestRedisStore(t, 3, time.Minute)

	for i := 0; i < 3; i++ {
		if !store.Allow("alice") {
			t.Fatalf("request %d should have been allowed", i+1)
		}
	}
	if store.Allow("alice") {
		t.Fatal("4th request must be rejected — limit is 3 per window")
	}
}

func TestRedisRateStore_PerKeyIsolation(t *testing.T) {
	store, _ := newTestRedisStore(t, 1, time.Minute)

	if !store.Allow("alice") {
		t.Fatal("alice's first request should pass")
	}
	if store.Allow("alice") {
		t.Fatal("alice's second must be rejected — limit is 1")
	}
	// bob starts fresh — keys don't share budget.
	if !store.Allow("bob") {
		t.Fatal("bob's first request should pass, per-key isolation broken")
	}
}

func TestRedisRateStore_WindowSlides(t *testing.T) {
	store, mr := newTestRedisStore(t, 2, 100*time.Millisecond)

	if !store.Allow("alice") {
		t.Fatal("1st request should pass")
	}
	if !store.Allow("alice") {
		t.Fatal("2nd request should pass")
	}
	if store.Allow("alice") {
		t.Fatal("3rd request should be rejected")
	}
	// Fast-forward miniredis past the window; old entries become eligible
	// for ZREMRANGEBYSCORE inside the script.
	mr.FastForward(150 * time.Millisecond)
	if !store.Allow("alice") {
		t.Fatal("after window expires the budget should reset")
	}
}

// Fail-open on Redis errors: if the backend is unreachable we want traffic
// to flow through (with a log warning) rather than hard-fail requests. This
// is the documented behaviour of Allow().
func TestRedisRateStore_FailsOpenOnBackendDown(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store, err := NewRedisRateStore(client, 1, time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	// Kill Redis, then call Allow — it must return true (fail open) not panic.
	mr.Close()

	if !store.Allow("alice") {
		t.Fatal("with Redis down, Allow must fail open (return true)")
	}
}

func TestRedisRateStore_PingFailureDuringConstruction(t *testing.T) {
	// Unreachable port — construction should error (fail closed on
	// startup so misconfiguration surfaces immediately).
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer func() { _ = client.Close() }()
	if _, err := NewRedisRateStore(client, 10, time.Minute, nil); err == nil {
		t.Fatal("expected construction error when Redis is unreachable")
	}
}
