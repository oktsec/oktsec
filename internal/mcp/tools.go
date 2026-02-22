package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
)

type handlers struct {
	cfg     *config.Config
	scanner *engine.Scanner
	audit   *audit.Store
	keys    *identity.KeyStore
	logger  *slog.Logger
}

// --- Tool definitions ---

func scanMessageTool() mcplib.Tool {
	return mcplib.NewTool("scan_message",
		mcplib.WithDescription(
			"Scan an inter-agent message for security threats. "+
				"Checks for prompt injection, credential leaks, PII exposure, relay injection, "+
				"and 140+ other threat patterns.",
		),
		mcplib.WithString("content",
			mcplib.Required(),
			mcplib.Description("The message content to scan"),
		),
		mcplib.WithString("from",
			mcplib.Description("Sender agent name"),
		),
		mcplib.WithString("to",
			mcplib.Description("Recipient agent name"),
		),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

func listAgentsTool() mcplib.Tool {
	return mcplib.NewTool("list_agents",
		mcplib.WithDescription(
			"List all agents configured in the oktsec policy, including their access control rules.",
		),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

func auditQueryTool() mcplib.Tool {
	return mcplib.NewTool("audit_query",
		mcplib.WithDescription(
			"Query the oktsec audit log. Returns recent inter-agent messages with status, "+
				"policy decisions, and security findings.",
		),
		mcplib.WithString("status",
			mcplib.Description("Filter by status: delivered, blocked, rejected, quarantined"),
		),
		mcplib.WithString("agent",
			mcplib.Description("Filter by agent name (matches from or to)"),
		),
		mcplib.WithNumber("limit",
			mcplib.Description("Maximum entries to return (default 20)"),
		),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

func getPolicyTool() mcplib.Tool {
	return mcplib.NewTool("get_policy",
		mcplib.WithDescription(
			"Get the security policy for a specific agent, including which agents it can message "+
				"and what content restrictions apply.",
		),
		mcplib.WithString("agent",
			mcplib.Required(),
			mcplib.Description("Agent name to look up"),
		),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

func verifyAgentTool() mcplib.Tool {
	return mcplib.NewTool("verify_agent",
		mcplib.WithDescription(
			"Verify an Ed25519 signature from an agent. Checks that the message was "+
				"signed by the claimed sender using their registered public key.",
		),
		mcplib.WithString("agent",
			mcplib.Required(),
			mcplib.Description("Agent name who claims to have signed the message"),
		),
		mcplib.WithString("from",
			mcplib.Required(),
			mcplib.Description("Sender agent name (used in canonical payload)"),
		),
		mcplib.WithString("to",
			mcplib.Required(),
			mcplib.Description("Recipient agent name (used in canonical payload)"),
		),
		mcplib.WithString("content",
			mcplib.Required(),
			mcplib.Description("Message content that was signed"),
		),
		mcplib.WithString("timestamp",
			mcplib.Required(),
			mcplib.Description("Timestamp used when signing (RFC3339)"),
		),
		mcplib.WithString("signature",
			mcplib.Required(),
			mcplib.Description("Base64-encoded Ed25519 signature"),
		),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

func reviewQuarantineTool() mcplib.Tool {
	return mcplib.NewTool("review_quarantine",
		mcplib.WithDescription(
			"Review and manage quarantined messages. List pending items, view details, "+
				"or approve/reject messages held for human review.",
		),
		mcplib.WithString("action",
			mcplib.Required(),
			mcplib.Description("Action to perform: list, detail, approve, reject"),
		),
		mcplib.WithString("id",
			mcplib.Description("Quarantine item ID (required for detail, approve, reject)"),
		),
		mcplib.WithNumber("limit",
			mcplib.Description("Maximum items to return for list action (default 20)"),
		),
		mcplib.WithString("status",
			mcplib.Description("Filter by status for list action: pending, approved, rejected, expired"),
		),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
	)
}

// --- Handlers ---

func (h *handlers) handleScanMessage(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	content := request.GetString("content", "")
	if content == "" {
		return mcplib.NewToolResultError("content is required"), nil
	}

	from := request.GetString("from", "")
	to := request.GetString("to", "")

	outcome, err := h.scanner.ScanContent(ctx, content)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	type finding struct {
		RuleID   string `json:"rule_id"`
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Match    string `json:"match"`
	}

	var findings []finding
	for _, f := range outcome.Findings {
		findings = append(findings, finding{
			RuleID:   f.RuleID,
			Name:     f.Name,
			Severity: f.Severity,
			Match:    f.Match,
		})
	}

	result := map[string]any{
		"verdict":  string(outcome.Verdict),
		"findings": findings,
		"from":     from,
		"to":       to,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcplib.NewToolResultText(string(data)), nil
}

func (h *handlers) handleListAgents(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	type agentInfo struct {
		Name           string   `json:"name"`
		CanMessage     []string `json:"can_message"`
		BlockedContent []string `json:"blocked_content,omitempty"`
	}

	var agents []agentInfo
	for name, agent := range h.cfg.Agents {
		agents = append(agents, agentInfo{
			Name:           name,
			CanMessage:     agent.CanMessage,
			BlockedContent: agent.BlockedContent,
		})
	}

	result := map[string]any{
		"agents":            agents,
		"total":             len(agents),
		"require_signature": h.cfg.Identity.RequireSignature,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcplib.NewToolResultText(string(data)), nil
}

func (h *handlers) handleAuditQuery(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	status := request.GetString("status", "")
	agent := request.GetString("agent", "")
	limit := request.GetInt("limit", 0)
	if limit <= 0 {
		limit = 20
	}

	entries, err := h.audit.Query(audit.QueryOpts{
		Status: status,
		Agent:  agent,
		Limit:  limit,
	})
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
	}

	data, _ := json.MarshalIndent(entries, "", "  ")
	return mcplib.NewToolResultText(string(data)), nil
}

func (h *handlers) handleGetPolicy(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	agentName := request.GetString("agent", "")
	if agentName == "" {
		return mcplib.NewToolResultError("agent is required"), nil
	}

	agent, ok := h.cfg.Agents[agentName]
	if !ok {
		known := make([]string, 0, len(h.cfg.Agents))
		for name := range h.cfg.Agents {
			known = append(known, name)
		}
		return mcplib.NewToolResultText(fmt.Sprintf("Agent %q not found. Known agents: %s", agentName, strings.Join(known, ", "))), nil
	}

	result := map[string]any{
		"agent":             agentName,
		"can_message":       agent.CanMessage,
		"blocked_content":   agent.BlockedContent,
		"require_signature": h.cfg.Identity.RequireSignature,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcplib.NewToolResultText(string(data)), nil
}

func (h *handlers) handleVerifyAgent(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	agentName := request.GetString("agent", "")
	from := request.GetString("from", "")
	to := request.GetString("to", "")
	content := request.GetString("content", "")
	timestamp := request.GetString("timestamp", "")
	signature := request.GetString("signature", "")

	if agentName == "" || from == "" || to == "" || content == "" || timestamp == "" || signature == "" {
		return mcplib.NewToolResultError("agent, from, to, content, timestamp, and signature are all required"), nil
	}

	if h.keys == nil {
		return mcplib.NewToolResultError("no keystore configured — keys are needed for verification"), nil
	}

	pubKey, ok := h.keys.Get(agentName)
	if !ok {
		known := h.keys.Names()
		result := map[string]any{
			"verified": false,
			"error":    fmt.Sprintf("no public key for agent %q", agentName),
			"known":    known,
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		return mcplib.NewToolResultText(string(data)), nil
	}

	vr := identity.VerifyMessage(pubKey, from, to, content, timestamp, signature)

	result := map[string]any{
		"verified":    vr.Verified,
		"agent":       agentName,
		"fingerprint": vr.Fingerprint,
	}
	if vr.Error != nil {
		result["error"] = vr.Error.Error()
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcplib.NewToolResultText(string(data)), nil
}

func (h *handlers) handleReviewQuarantine(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	action := request.GetString("action", "")
	id := request.GetString("id", "")
	limit := request.GetInt("limit", 0)
	if limit <= 0 {
		limit = 20
	}
	status := request.GetString("status", "pending")

	switch action {
	case "list":
		items, err := h.audit.QuarantineQuery(status, "", limit)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
		}
		type itemSummary struct {
			ID        string `json:"id"`
			From      string `json:"from"`
			To        string `json:"to"`
			Status    string `json:"status"`
			Preview   string `json:"content_preview"`
			CreatedAt string `json:"created_at"`
			ExpiresAt string `json:"expires_at"`
		}
		var summaries []itemSummary
		for _, item := range items {
			preview := item.Content
			if len(preview) > 100 {
				preview = preview[:100] + "..."
			}
			summaries = append(summaries, itemSummary{
				ID:        item.ID,
				From:      item.FromAgent,
				To:        item.ToAgent,
				Status:    item.Status,
				Preview:   preview,
				CreatedAt: item.CreatedAt,
				ExpiresAt: item.ExpiresAt,
			})
		}
		out, _ := json.MarshalIndent(map[string]any{"items": summaries, "count": len(summaries)}, "", "  ")
		return mcplib.NewToolResultText(string(out)), nil

	case "detail":
		if id == "" {
			return mcplib.NewToolResultError("id is required for detail action"), nil
		}
		item, err := h.audit.QuarantineByID(id)
		if err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
		}
		if item == nil {
			return mcplib.NewToolResultError(fmt.Sprintf("quarantine item %q not found", id)), nil
		}
		out, _ := json.MarshalIndent(item, "", "  ")
		return mcplib.NewToolResultText(string(out)), nil

	case "approve":
		if id == "" {
			return mcplib.NewToolResultError("id is required for approve action"), nil
		}
		if err := h.audit.QuarantineApprove(id, "mcp"); err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("approve failed: %v", err)), nil
		}
		out, _ := json.MarshalIndent(map[string]string{"status": "approved", "id": id}, "", "  ")
		return mcplib.NewToolResultText(string(out)), nil

	case "reject":
		if id == "" {
			return mcplib.NewToolResultError("id is required for reject action"), nil
		}
		if err := h.audit.QuarantineReject(id, "mcp"); err != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("reject failed: %v", err)), nil
		}
		out, _ := json.MarshalIndent(map[string]string{"status": "rejected", "id": id}, "", "  ")
		return mcplib.NewToolResultText(string(out)), nil

	default:
		return mcplib.NewToolResultError("action must be one of: list, detail, approve, reject"), nil
	}
}
