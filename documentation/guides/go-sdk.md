# Go SDK

The `sdk` package provides a Go client for sending messages through the Oktsec proxy.

## Installation

```bash
go get github.com/oktsec/oktsec/sdk
```

## Basic usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/oktsec/oktsec/sdk"
)

func main() {
    // Without signing (observe mode)
    c := sdk.NewClient("http://localhost:8080", "my-agent", nil)

    resp, err := c.SendMessage(context.Background(), "recipient", "hello")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(resp.Status)          // "delivered"
    fmt.Println(resp.PolicyDecision)  // "allow"
    fmt.Println(resp.RulesTriggered)  // []
}
```

## With Ed25519 signing

```go
kp, err := sdk.LoadKeypair("./keys", "my-agent")
if err != nil {
    log.Fatal(err)
}

c := sdk.NewClient("http://localhost:8080", "my-agent", kp.PrivateKey)
resp, err := c.SendMessage(ctx, "recipient", "hello")
// resp.VerifiedSender == true
```

## With metadata

```go
resp, err := c.SendMessageWithMetadata(ctx, "recipient", "hello", map[string]string{
    "task_id": "abc-123",
    "session": "xyz",
})
```

## Health check

```go
health, err := c.Health(ctx)
fmt.Println(health.Status)   // "ok"
fmt.Println(health.Version)  // "0.8.1"
```

## Response types

```go
type MessageResponse struct {
    Status         string           `json:"status"`
    MessageID      string           `json:"message_id"`
    PolicyDecision string           `json:"policy_decision"`
    RulesTriggered []FindingSummary `json:"rules_triggered"`
    VerifiedSender bool             `json:"verified_sender"`
    QuarantineID   string           `json:"quarantine_id,omitempty"`
    ExpiresAt      string           `json:"expires_at,omitempty"`
}
```

Policy decisions: `allow`, `content_flagged`, `content_quarantined`, `content_blocked`, `identity_rejected`, `signature_required`, `acl_denied`, `agent_suspended`, `recipient_suspended`.
