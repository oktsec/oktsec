package identity

import (
	"testing"
	"time"
)

func TestEphemeralKeyStore_Issue(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	kp, err := store.Issue("task-1", "parent-fp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	if kp.TaskID != "task-1" {
		t.Errorf("task = %q, want task-1", kp.TaskID)
	}
	if kp.ParentKey != "parent-fp" {
		t.Errorf("parent = %q", kp.ParentKey)
	}
	if kp.IsExpired() {
		t.Error("should not be expired")
	}
	if kp.TTLRemaining() < 59*time.Minute {
		t.Errorf("TTL = %v, want ~1h", kp.TTLRemaining())
	}
	if store.ActiveCount() != 1 {
		t.Errorf("active = %d, want 1", store.ActiveCount())
	}
}

func TestEphemeralKeyStore_Verify(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	kp, _ := store.Issue("task-1", "parent-fp", time.Hour)

	// Verify by public key
	found := store.Verify(kp.PublicKey)
	if found == nil {
		t.Fatal("should find ephemeral key")
	}
	if found.TaskID != "task-1" {
		t.Errorf("task = %q", found.TaskID)
	}

	// Verify by fingerprint
	fp := Fingerprint(kp.PublicKey)
	found2 := store.VerifyByFingerprint(fp)
	if found2 == nil {
		t.Fatal("should find by fingerprint")
	}
}

func TestEphemeralKeyStore_NegativeTTLRejected(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	_, err := store.Issue("task-1", "parent-fp", -time.Hour)
	if err == nil {
		t.Fatal("negative TTL should be rejected")
	}
}

func TestEphemeralKeyStore_MaxPerTask(t *testing.T) {
	store := NewEphemeralKeyStore(2, 24*time.Hour) // max 2 per task
	defer store.Close()

	_, err := store.Issue("task-1", "fp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Issue("task-1", "fp", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Issue("task-1", "fp", time.Hour)
	if err == nil {
		t.Fatal("should reject 3rd key for same task")
	}

	// Different task should work
	_, err = store.Issue("task-2", "fp", time.Hour)
	if err != nil {
		t.Fatalf("different task should work: %v", err)
	}
}

func TestEphemeralKeyStore_MaxTTLCapped(t *testing.T) {
	store := NewEphemeralKeyStore(10, time.Hour) // max 1h
	defer store.Close()

	kp, _ := store.Issue("task-1", "fp", 48*time.Hour) // request 48h

	// Should be capped to 1h
	if kp.TTLRemaining() > time.Hour+time.Second {
		t.Errorf("TTL = %v, should be capped to 1h", kp.TTLRemaining())
	}
}

func TestEphemeralKeyStore_Revoke(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	kp, _ := store.Issue("task-1", "fp", time.Hour)
	fp := Fingerprint(kp.PublicKey)

	if !store.Revoke(fp) {
		t.Fatal("revoke should return true")
	}
	if store.ActiveCount() != 0 {
		t.Errorf("active = %d after revoke", store.ActiveCount())
	}
	if store.Verify(kp.PublicKey) != nil {
		t.Error("revoked key should not verify")
	}
}

func TestEphemeralKeyStore_RevokeByTask(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	_, _ = store.Issue("task-1", "fp", time.Hour)
	_, _ = store.Issue("task-1", "fp", time.Hour)
	_, _ = store.Issue("task-2", "fp", time.Hour)

	revoked := store.RevokeByTask("task-1")
	if revoked != 2 {
		t.Errorf("revoked = %d, want 2", revoked)
	}
	if store.ActiveCount() != 1 {
		t.Errorf("active = %d, want 1 (task-2)", store.ActiveCount())
	}
	if store.TaskCount() != 1 {
		t.Errorf("tasks = %d, want 1", store.TaskCount())
	}
}

func TestEphemeralKeyStore_RevokeNonExistent(t *testing.T) {
	store := NewEphemeralKeyStore(10, 24*time.Hour)
	defer store.Close()

	if store.Revoke("nonexistent") {
		t.Error("revoking nonexistent key should return false")
	}
}
