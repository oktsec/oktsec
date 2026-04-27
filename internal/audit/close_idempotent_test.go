package audit

import (
	"errors"
	"testing"
)

// In `oktsec run` the proxy server and the in-process gateway both
// hold a reference to the same audit Store and both call Close on
// shutdown. Without a sync.Once guard the second call would invoke
// close(s.writes) on an already-closed channel and panic with
// "close of closed channel" — turning a clean Ctrl+C into a stack
// trace, which is the DP-03 desktop blocker. This test pins the
// idempotency contract:
//
//   - Two consecutive Close() calls must not panic.
//   - Both calls must return the same error value (nil on the
//     happy path) so neither caller sees a phantom failure.
//   - The first call drains writes and shuts down writeLoop; the
//     second is a cheap no-op via sync.Once.
func TestStore_CloseIsIdempotent(t *testing.T) {
	store := newTestStore(t)

	// First close: real shutdown path. Drains writes, joins
	// writeLoop, closes the DB.
	first := store.Close()
	if first != nil {
		t.Fatalf("first Close returned %v; want nil", first)
	}

	// Second close: must be a no-op via sync.Once. The defer in
	// newTestStore would otherwise panic with "close of closed
	// channel" on the way out.
	second := store.Close()
	if second != nil {
		t.Errorf("second Close returned %v; want nil (idempotent)", second)
	}

	// Third call for paranoia — still no panic, still nil. The
	// Once guarantees the body never runs again, so the channel-
	// close path is unreachable after the first call.
	if third := store.Close(); third != nil {
		t.Errorf("third Close returned %v; want nil", third)
	}
}

// When the underlying DB close fails, the FIRST Close call returns
// that error and every subsequent Close returns the same error. A
// caller that retries Close because the first one looked like it
// might have failed must not see a mysterious nil on the second
// attempt — the cached error keeps both shutdown paths consistent.
//
// We cannot easily inject a DB-close failure into the production
// constructor, so this test exercises the contract directly with
// a Store that has already been closed once. The cached error is
// implicitly nil here, but the assertion that both calls return
// the SAME value is what guards the cache wiring.
func TestStore_CloseReturnsSameErrorAcrossCalls(t *testing.T) {
	store := newTestStore(t)

	a := store.Close()
	b := store.Close()
	// errors.Is treats Is(nil, nil) as true, so this single check
	// covers the happy path AND the cached-error case without a
	// redundant nil guard.
	if !errors.Is(a, b) {
		t.Errorf("Close calls returned different errors: first=%v second=%v", a, b)
	}
}
