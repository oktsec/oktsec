package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/config"
	"github.com/oktsec/oktsec/internal/engine"
	"github.com/oktsec/oktsec/internal/identity"
	"github.com/oktsec/oktsec/internal/mcputil"
)

type handlers struct {
	cfg     *config.Config
	scanner *engine.Scanner
	audit   *audit.Store
	keys    *identity.KeyStore
	logger  *slog.Logger
}

// --- Tool definitions ---

// jsonSchema builds a minimal JSON Schema object for tool InputSchema.
func jsonSchema(properties map[string]any, required []string) map[string]any {
	s := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func scanMessageTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "scan_message",
		Description: "Scan an inter-agent message for security threats. " +
			"Checks for prompt injection, credential leaks, PII exposure, relay injection, " +
			"and 140+ other threat patterns.",
		InputSchema: jsonSchema(map[string]any{
			"content": prop("string", "The message content to scan"),
			"from":    prop("string", "Sender agent name"),
			"to":      prop("string", "Recipient agent name"),
		}, []string{"content"}),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}
}

func listAgentsTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "list_agents",
		Description: "List all agents configured in the oktsec policy, " +
			"including their access control rules.",
		InputSchema: jsonSchema(nil, nil),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}
}

func auditQueryTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "audit_query",
		Description: "Query the oktsec audit log. Returns recent inter-agent messages " +
			"with status, policy decisions, and security findings.",
		InputSchema: jsonSchema(map[string]any{
			"status": prop("string", "Filter by status: delivered, blocked, rejected, quarantined"),
			"agent":  prop("string", "Filter by agent name (matches from or to)"),
			"limit":  prop("number", "Maximum entries to return (default 20)"),
		}, nil),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}
}

func getPolicyTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "get_policy",
		Description: "Get the security policy for a specific agent, including which agents " +
			"it can message and what content restrictions apply.",
		InputSchema: jsonSchema(map[string]any{
			"agent": prop("string", "Agent name to look up"),
		}, []string{"agent"}),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}
}

func verifyAgentTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "verify_agent",
		Description: "Verify an Ed25519 signature from an agent. Checks that the message " +
			"was signed by the claimed sender using their registered public key.",
		InputSchema: jsonSchema(map[string]any{
			"agent":     prop("string", "Agent name who claims to have signed the message"),
			"from":      prop("string", "Sender agent name (used in canonical payload)"),
			"to":        prop("string", "Recipient agent name (used in canonical payload)"),
			"content":   prop("string", "Message content that was signed"),
			"timestamp": prop("string", "Timestamp used when signing (RFC3339)"),
			"signature": prop("string", "Base64-encoded Ed25519 signature"),
		}, []string{"agent", "from", "to", "content", "timestamp", "signature"}),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}
}

func reviewQuarantineTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "review_quarantine",
		Description: "Review and manage quarantined messages. List pending items, " +
			"view details, or approve/reject messages held for human review.",
		InputSchema: jsonSchema(map[string]any{
			"action": prop("string", "Action to perform: list, detail, approve, reject"),
			"id":     prop("string", "Quarantine item ID (required for detail, approve, reject)"),
			"limit":  prop("number", "Maximum items to return for list action (default 20)"),
			"status": prop("string", "Filter by status for list action: pending, approved, rejected, expired"),
		}, []string{"action"}),
	}
}

func boolPtr(b bool) *bool { return &b }

// --- Handlers ---

func (h *handlers) handleScanMessage(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments
	content := mcputil.GetString(args, "content", "")
	if content == "" {
		return mcputil.NewToolResultError("content is required"), nil
	}

	from := mcputil.GetString(args, "from", "")
	to := mcputil.GetString(args, "to", "")

	outcome, err := h.scanner.ScanContent(context.Background(), content)
	if err != nil {
		return mcputil.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
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
	return mcputil.NewToolResultText(string(data)), nil
}

func (h *handlers) handleListAgents(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	return mcputil.NewToolResultText(string(data)), nil
}

func (h *handlers) handleAuditQuery(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments
	status := mcputil.GetString(args, "status", "")
	agent := mcputil.GetString(args, "agent", "")
	limit := mcputil.GetInt(args, "limit", 0)
	if limit <= 0 {
		limit = 20
	}

	entries, err := h.audit.Query(audit.QueryOpts{
		Status: status,
		Agent:  agent,
		Limit:  limit,
	})
	if err != nil {
		return mcputil.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
	}

	data, _ := json.MarshalIndent(entries, "", "  ")
	return mcputil.NewToolResultText(string(data)), nil
}

func (h *handlers) handleGetPolicy(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments
	agentName := mcputil.GetString(args, "agent", "")
	if agentName == "" {
		return mcputil.NewToolResultError("agent is required"), nil
	}

	agent, ok := h.cfg.Agents[agentName]
	if !ok {
		known := make([]string, 0, len(h.cfg.Agents))
		for name := range h.cfg.Agents {
			known = append(known, name)
		}
		return mcputil.NewToolResultText(fmt.Sprintf("Agent %q not found. Known agents: %s", agentName, strings.Join(known, ", "))), nil
	}

	result := map[string]any{
		"agent":             agentName,
		"can_message":       agent.CanMessage,
		"blocked_content":   agent.BlockedContent,
		"require_signature": h.cfg.Identity.RequireSignature,
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return mcputil.NewToolResultText(string(data)), nil
}

func (h *handlers) handleVerifyAgent(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments
	agentName := mcputil.GetString(args, "agent", "")
	from := mcputil.GetString(args, "from", "")
	to := mcputil.GetString(args, "to", "")
	content := mcputil.GetString(args, "content", "")
	timestamp := mcputil.GetString(args, "timestamp", "")
	signature := mcputil.GetString(args, "signature", "")

	if agentName == "" || from == "" || to == "" || content == "" || timestamp == "" || signature == "" {
		return mcputil.NewToolResultError("agent, from, to, content, timestamp, and signature are all required"), nil
	}

	if h.keys == nil {
		return mcputil.NewToolResultError("no keystore configured — keys are needed for verification"), nil
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
		return mcputil.NewToolResultText(string(data)), nil
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
	return mcputil.NewToolResultText(string(data)), nil
}

func (h *handlers) handleReviewQuarantine(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := request.Params.Arguments
	action := mcputil.GetString(args, "action", "")
	id := mcputil.GetString(args, "id", "")

	switch action {
	case "list":
		return h.quarantineList(args)
	case "detail":
		return h.quarantineDetail(id)
	case "approve":
		return h.quarantineDecide(id, "approve")
	case "reject":
		return h.quarantineDecide(id, "reject")
	default:
		return mcputil.NewToolResultError("action must be one of: list, detail, approve, reject"), nil
	}
}

type quarantineSummary struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Status    string `json:"status"`
	Preview   string `json:"content_preview"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

func (h *handlers) quarantineList(args json.RawMessage) (*mcp.CallToolResult, error) {
	limit := mcputil.GetInt(args, "limit", 0)
	if limit <= 0 {
		limit = 20
	}
	status := mcputil.GetString(args, "status", "pending")

	items, err := h.audit.QuarantineQuery(status, "", limit)
	if err != nil {
		return mcputil.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
	}
	var summaries []quarantineSummary
	for _, item := range items {
		preview := item.Content
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		summaries = append(summaries, quarantineSummary{
			ID: item.ID, From: item.FromAgent, To: item.ToAgent,
			Status: item.Status, Preview: preview,
			CreatedAt: item.CreatedAt, ExpiresAt: item.ExpiresAt,
		})
	}
	out, _ := json.MarshalIndent(map[string]any{"items": summaries, "count": len(summaries)}, "", "  ")
	return mcputil.NewToolResultText(string(out)), nil
}

func (h *handlers) quarantineDetail(id string) (*mcp.CallToolResult, error) {
	if id == "" {
		return mcputil.NewToolResultError("id is required for detail action"), nil
	}
	item, err := h.audit.QuarantineByID(id)
	if err != nil {
		return mcputil.NewToolResultError(fmt.Sprintf("query failed: %v", err)), nil
	}
	if item == nil {
		return mcputil.NewToolResultError(fmt.Sprintf("quarantine item %q not found", id)), nil
	}
	out, _ := json.MarshalIndent(item, "", "  ")
	return mcputil.NewToolResultText(string(out)), nil
}

func (h *handlers) quarantineDecide(id, action string) (*mcp.CallToolResult, error) {
	if id == "" {
		return mcputil.NewToolResultError(fmt.Sprintf("id is required for %s action", action)), nil
	}
	var err error
	if action == "approve" {
		err = h.audit.QuarantineApprove(id, "mcp")
	} else {
		err = h.audit.QuarantineReject(id, "mcp")
	}
	if err != nil {
		return mcputil.NewToolResultError(fmt.Sprintf("%s failed: %v", action, err)), nil
	}
	status := action + "d" // approved or rejected
	out, _ := json.MarshalIndent(map[string]string{"status": status, "id": id}, "", "  ")
	return mcputil.NewToolResultText(string(out)), nil
}
