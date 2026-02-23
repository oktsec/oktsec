package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("http://localhost:8080", "test-agent", nil)
	if c.baseURL != "http://localhost:8080" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.agentName != "test-agent" {
		t.Errorf("agentName = %q", c.agentName)
	}
	if c.privateKey != nil {
		t.Error("expected nil private key")
	}
}

func TestSendMessage_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/message" {
			t.Errorf("path = %s", r.URL.Path)
		}

		var req MessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if req.From != "sender" {
			t.Errorf("from = %q", req.From)
		}
		if req.To != "receiver" {
			t.Errorf("to = %q", req.To)
		}
		if req.Content != "hello" {
			t.Errorf("content = %q", req.Content)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MessageResponse{
			Status:         "delivered",
			MessageID:      "msg-123",
			PolicyDecision: "allow",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sender", nil)
	resp, err := c.SendMessage(context.Background(), "receiver", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "delivered" {
		t.Errorf("status = %q", resp.Status)
	}
	if resp.PolicyDecision != "allow" {
		t.Errorf("decision = %q", resp.PolicyDecision)
	}
}

func TestSendMessage_Blocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MessageResponse{
			Status:         "blocked",
			MessageID:      "msg-456",
			PolicyDecision: "content_blocked",
			RulesTriggered: []FindingSummary{{RuleID: "IAP-001", Severity: "critical"}},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sender", nil)
	resp, err := c.SendMessage(context.Background(), "receiver", "malicious content")

	if err == nil {
		t.Fatal("expected error for blocked message")
	}

	pe, ok := err.(*PolicyError)
	if !ok {
		t.Fatalf("expected PolicyError, got %T", err)
	}
	if pe.StatusCode != 403 {
		t.Errorf("status code = %d", pe.StatusCode)
	}
	if pe.Response.PolicyDecision != "content_blocked" {
		t.Errorf("decision = %q", pe.Response.PolicyDecision)
	}

	// Response should still be available
	if resp == nil {
		t.Fatal("expected response even on error")
	}
	if len(resp.RulesTriggered) != 1 {
		t.Errorf("rules = %d", len(resp.RulesTriggered))
	}
}

func TestSendMessage_Quarantined(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(MessageResponse{
			Status:         "quarantined",
			MessageID:      "msg-789",
			PolicyDecision: "content_quarantined",
			QuarantineID:   "q-001",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sender", nil)
	resp, err := c.SendMessage(context.Background(), "receiver", "suspicious content")

	pe, ok := err.(*PolicyError)
	if !ok {
		t.Fatalf("expected PolicyError, got %T: %v", err, err)
	}
	if pe.StatusCode != 202 {
		t.Errorf("status code = %d", pe.StatusCode)
	}
	if resp.QuarantineID != "q-001" {
		t.Errorf("quarantine_id = %q", resp.QuarantineID)
	}
}

func TestSendMessage_WithSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req MessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		gotSig = req.Signature

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MessageResponse{
			Status:         "delivered",
			MessageID:      "msg-signed",
			PolicyDecision: "allow",
			VerifiedSender: true,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "signer", priv)
	resp, err := c.SendMessage(context.Background(), "receiver", "signed message")
	if err != nil {
		t.Fatal(err)
	}
	if gotSig == "" {
		t.Error("expected signature in request")
	}
	if !resp.VerifiedSender {
		t.Error("expected verified_sender=true")
	}
}

func TestSendMessage_WithMetadata(t *testing.T) {
	var gotMeta map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req MessageRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		gotMeta = req.Metadata

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(MessageResponse{
			Status: "delivered", MessageID: "msg-meta", PolicyDecision: "allow",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "sender", nil)
	meta := map[string]string{"task": "research", "priority": "high"}
	_, err := c.SendMessageWithMetadata(context.Background(), "receiver", "hello", meta)
	if err != nil {
		t.Fatal(err)
	}
	if gotMeta["task"] != "research" {
		t.Errorf("metadata task = %q", gotMeta["task"])
	}
}

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HealthResponse{Status: "ok", Version: "0.4.1"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "agent", nil)
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q", resp.Status)
	}
	if resp.Version != "0.4.1" {
		t.Errorf("version = %q", resp.Version)
	}
}

func TestLoadKeypair(t *testing.T) {
	// Generate and save a keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub

	dir := t.TempDir()

	// Write private key PEM
	privPEM := "-----BEGIN OKTSEC ED25519 PRIVATE KEY-----\n"
	privPEM += encodeBase64Lines(priv)
	privPEM += "-----END OKTSEC ED25519 PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "test.key"), []byte(privPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	kp, err := LoadKeypair(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if kp.Name != "test" {
		t.Errorf("name = %q", kp.Name)
	}
	if len(kp.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d", len(kp.PrivateKey))
	}
	if len(kp.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d", len(kp.PublicKey))
	}
}

func TestLoadKeypair_NotFound(t *testing.T) {
	_, err := LoadKeypair(t.TempDir(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestSign(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sig := sign(priv, "from", "to", "content", "2026-01-01T00:00:00Z")
	if sig == "" {
		t.Error("expected non-empty signature")
	}
	// Signature should be base64
	if len(sig) < 10 {
		t.Errorf("signature too short: %q", sig)
	}
}

func TestPolicyError_Error(t *testing.T) {
	pe := &PolicyError{
		StatusCode: 403,
		Response: MessageResponse{
			Status:         "blocked",
			PolicyDecision: "content_blocked",
			MessageID:      "msg-001",
		},
	}
	msg := pe.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

// encodeBase64Lines encodes bytes to base64 with line wrapping for PEM.
func encodeBase64Lines(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	var result string
	for len(encoded) > 64 {
		result += encoded[:64] + "\n"
		encoded = encoded[64:]
	}
	if len(encoded) > 0 {
		result += encoded + "\n"
	}
	return result
}
