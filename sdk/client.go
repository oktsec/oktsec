// Package sdk provides a Go client for the oktsec security proxy.
//
// Basic usage:
//
//	c := sdk.NewClient("http://localhost:8080", "my-agent", nil)
//	resp, err := c.SendMessage(ctx, "recipient", "hello")
//
// With Ed25519 signing:
//
//	kp, _ := sdk.LoadKeypair("./keys", "my-agent")
//	c := sdk.NewClient("http://localhost:8080", "my-agent", kp.PrivateKey)
//	resp, err := c.SendMessage(ctx, "recipient", "hello")
package sdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// MessageRequest is sent to POST /v1/message.
type MessageRequest struct {
	From      string            `json:"from"`
	To        string            `json:"to"`
	Content   string            `json:"content"`
	Signature string            `json:"signature,omitempty"`
	Timestamp string            `json:"timestamp"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// MessageResponse is returned by the oktsec proxy.
type MessageResponse struct {
	Status         string           `json:"status"`          // delivered, blocked, quarantined
	MessageID      string           `json:"message_id"`      // UUID
	PolicyDecision string           `json:"policy_decision"` // allow, content_flagged, content_blocked, etc.
	RulesTriggered []FindingSummary `json:"rules_triggered"`
	VerifiedSender bool             `json:"verified_sender"`
	QuarantineID   string           `json:"quarantine_id,omitempty"`
}

// FindingSummary describes a triggered detection rule.
type FindingSummary struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category,omitempty"`
	Match    string `json:"match,omitempty"`
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// PolicyError is returned when the proxy rejects a message.
type PolicyError struct {
	StatusCode int
	Response   MessageResponse
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("oktsec: %s (HTTP %d, decision=%s, id=%s)",
		e.Response.Status, e.StatusCode, e.Response.PolicyDecision, e.Response.MessageID)
}

// Client sends messages through an oktsec proxy.
type Client struct {
	baseURL    string
	agentName  string
	privateKey ed25519.PrivateKey // nil = unsigned
	httpClient *http.Client
}

// NewClient creates a client for the oktsec proxy.
// Pass nil for privateKey to send unsigned messages.
func NewClient(baseURL, agentName string, privateKey ed25519.PrivateKey) *Client {
	return &Client{
		baseURL:    baseURL,
		agentName:  agentName,
		privateKey: privateKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// SendMessage sends a message to another agent through the proxy.
// Returns a PolicyError for blocked (403), quarantined (202), unauthorized (401),
// and rate-limited (429) responses.
func (c *Client) SendMessage(ctx context.Context, to, content string) (*MessageResponse, error) {
	return c.SendMessageWithMetadata(ctx, to, content, nil)
}

// SendMessageWithMetadata sends a message with optional metadata.
func (c *Client) SendMessageWithMetadata(ctx context.Context, to, content string, metadata map[string]string) (*MessageResponse, error) {
	ts := time.Now().UTC().Format(time.RFC3339)

	req := MessageRequest{
		From:      c.agentName,
		To:        to,
		Content:   content,
		Timestamp: ts,
		Metadata:  metadata,
	}

	if c.privateKey != nil {
		req.Signature = sign(c.privateKey, c.agentName, to, content, ts)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/message", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer httpResp.Body.Close()

	var resp MessageResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decoding response (HTTP %d): %w", httpResp.StatusCode, err)
	}

	switch httpResp.StatusCode {
	case http.StatusOK:
		return &resp, nil
	default:
		return &resp, &PolicyError{StatusCode: httpResp.StatusCode, Response: resp}
	}
}

// Health checks the proxy health endpoint.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("health check: %w", err)
	}
	defer httpResp.Body.Close()

	var resp HealthResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decoding health: %w", err)
	}
	return &resp, nil
}

// Keypair holds an Ed25519 key pair loaded from disk.
type Keypair struct {
	Name       string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// LoadKeypair loads an oktsec keypair from PEM files in the given directory.
// Expects <dir>/<name>.key (private) and optionally <dir>/<name>.pub (public).
func LoadKeypair(dir, name string) (*Keypair, error) {
	privPath := filepath.Join(dir, name+".key")
	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	privBlock, _ := pem.Decode(privPEM)
	if privBlock == nil {
		return nil, fmt.Errorf("invalid PEM in %s", privPath)
	}
	priv := ed25519.PrivateKey(privBlock.Bytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &Keypair{Name: name, PublicKey: pub, PrivateKey: priv}, nil
}

// sign creates a base64 Ed25519 signature over the canonical message payload.
func sign(key ed25519.PrivateKey, from, to, content, timestamp string) string {
	payload := []byte(fmt.Sprintf("%s\n%s\n%s\n%s", from, to, content, timestamp))
	sig := ed25519.Sign(key, payload)
	return base64.StdEncoding.EncodeToString(sig)
}
