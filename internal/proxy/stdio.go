package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
)

// StdioProxy wraps an MCP server process, intercepting stdio JSON-RPC messages.
type StdioProxy struct {
	agent        string
	enforce      bool
	allowedTools map[string]bool // nil or empty = all tools allowed
	scanner      *engine.Scanner
	audit        *audit.Store
	logger       *slog.Logger

	// stdoutMu protects os.Stdout writes when both goroutines may write
	// (enforce mode: error injection writes to client stdout).
	stdoutMu sync.Mutex
}

// NewStdioProxy creates a proxy for intercepting MCP stdio communication.
// When enforce is true, malicious client→server requests are blocked and a
// JSON-RPC error response is injected back to the client.
func NewStdioProxy(agent string, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger, enforce bool) *StdioProxy {
	return &StdioProxy{
		agent:   agent,
		enforce: enforce,
		scanner: scanner,
		audit:   auditStore,
		logger:  logger,
	}
}

// SetAllowedTools configures a tool allowlist. When set, only listed tool
// names are permitted in tools/call requests. Empty list means all tools allowed.
func (p *StdioProxy) SetAllowedTools(tools []string) {
	if len(tools) == 0 {
		p.allowedTools = nil
		return
	}
	m := make(map[string]bool, len(tools))
	for _, t := range tools {
		m[t] = true
	}
	p.allowedTools = m
}

// Run starts the child process and proxies stdin/stdout, scanning each message.
func (p *StdioProxy) Run(ctx context.Context, command string, args []string) error {
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stderr = os.Stderr

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", command, err)
	}

	errCh := make(chan error, 2)

	// Client → oktsec → Server (stdin): can block + inject errors
	go func() {
		errCh <- p.proxyClientToServer(os.Stdin, childIn, os.Stdout)
		_ = childIn.Close()
	}()

	// Server → oktsec → Client (stdout): observe-only, always forwards
	go func() {
		errCh <- p.proxyServerToClient(childOut, os.Stdout)
	}()

	// Wait for first stream to end
	<-errCh

	// Wait for process to exit
	return cmd.Wait()
}

// jsonrpcMessage is the minimal structure needed to inspect JSON-RPC messages.
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

// jsonrpcError is a JSON-RPC 2.0 error response injected when a request is blocked.
type jsonrpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// proxyClientToServer handles client→server traffic.
// In enforce mode, blocked requests are not forwarded and a JSON-RPC error is
// injected back to the client.
func (p *StdioProxy) proxyClientToServer(clientRead io.Reader, serverWrite io.Writer, clientWrite io.Writer) error {
	sc := bufio.NewScanner(clientRead)
	sc.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line

	for sc.Scan() {
		line := sc.Bytes()

		blocked, rpcID, rule := p.inspectAndDecide(line, "client", p.agent)

		if blocked && p.enforce {
			// Inject JSON-RPC error back to client if this is a request (has id)
			if rpcID != nil {
				errResp := jsonrpcError{JSONRPC: "2.0", ID: rpcID}
				errResp.Error.Code = -32600
				errResp.Error.Message = "blocked by oktsec: " + rule

				if data, err := json.Marshal(errResp); err == nil {
					p.writeToClient(clientWrite, data)
				}
			}
			// Notifications (no id) are silently dropped
			continue
		}

		// Forward line as-is (transparent proxy)
		if _, err := serverWrite.Write(line); err != nil {
			return err
		}
		if _, err := serverWrite.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return sc.Err()
}

// proxyServerToClient handles server→client traffic.
// Always forwards (observe-only) — we never block server responses.
func (p *StdioProxy) proxyServerToClient(serverRead io.Reader, clientWrite io.Writer) error {
	sc := bufio.NewScanner(serverRead)
	sc.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for sc.Scan() {
		line := sc.Bytes()

		// Observe only — inspect but never block
		p.inspectAndLog(line, p.agent, "client")

		p.writeToClient(clientWrite, line)
	}
	return sc.Err()
}

// writeToClient writes a line + newline to the client, protected by mutex.
func (p *StdioProxy) writeToClient(w io.Writer, data []byte) {
	p.stdoutMu.Lock()
	defer p.stdoutMu.Unlock()
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

// inspectAndDecide scans a message and returns whether it should be blocked.
// Returns (blocked, rpcID, topRule).
func (p *StdioProxy) inspectAndDecide(line []byte, from, to string) (bool, json.RawMessage, string) {
	start := time.Now()
	msgID := uuid.New().String()

	var msg jsonrpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return false, nil, ""
	}

	// Tool allowlist check: block tools/call for tools not in the allowlist
	if p.enforce && msg.Method == "tools/call" && len(p.allowedTools) > 0 {
		toolName := extractToolName(msg)
		if toolName != "" && !p.allowedTools[toolName] {
			p.logger.Warn("tool not allowed",
				"tool", toolName,
				"agent", p.agent,
			)
			entry := audit.Entry{
				ID:             msgID,
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				FromAgent:      from,
				ToAgent:        to,
				ContentHash:    sha256Hash(toolName),
				Status:         "blocked",
				PolicyDecision: "tool_not_allowed",
				RulesTriggered: fmt.Sprintf(`[{"rule":"tool_allowlist","tool":"%s"}]`, toolName),
				LatencyMs:      time.Since(start).Milliseconds(),
			}
			p.audit.Log(entry)
			return true, msg.ID, "tool_allowlist:" + toolName
		}
	}

	content := extractContent(msg)
	if content == "" {
		return false, msg.ID, ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	outcome, err := p.scanner.ScanContent(ctx, content)
	if err != nil {
		p.logger.Error("scan failed", "error", err, "method", msg.Method)
		return false, msg.ID, ""
	}

	status, decision := verdictToStdio(outcome.Verdict)
	rulesJSON := encodeStdioFindings(outcome.Findings)
	topRule := ""
	if len(outcome.Findings) > 0 {
		topRule = outcome.Findings[0].RuleID
	}

	entry := audit.Entry{
		ID:             msgID,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		FromAgent:      from,
		ToAgent:        to,
		ContentHash:    sha256Hash(content),
		Status:         status,
		PolicyDecision: decision,
		RulesTriggered: rulesJSON,
		LatencyMs:      time.Since(start).Milliseconds(),
	}
	p.audit.Log(entry)

	if len(outcome.Findings) > 0 {
		p.logger.Warn("findings detected",
			"method", msg.Method,
			"from", from,
			"to", to,
			"findings", len(outcome.Findings),
			"verdict", outcome.Verdict,
		)
	}

	shouldBlock := outcome.Verdict == engine.VerdictBlock || outcome.Verdict == engine.VerdictQuarantine
	return shouldBlock, msg.ID, topRule
}

// inspectAndLog is the observe-only version for server→client traffic.
func (p *StdioProxy) inspectAndLog(line []byte, from, to string) {
	p.inspectAndDecide(line, from, to)
}

func verdictToStdio(v engine.ScanVerdict) (status, decision string) {
	switch v {
	case engine.VerdictBlock:
		return "blocked", "content_blocked"
	case engine.VerdictQuarantine:
		return "quarantined", "content_quarantined"
	case engine.VerdictFlag:
		return "delivered", "content_flagged"
	default:
		return "delivered", "allow"
	}
}

func encodeStdioFindings(findings []engine.FindingSummary) string {
	if len(findings) == 0 {
		return "[]"
	}
	if b, err := json.Marshal(findings); err == nil {
		return string(b)
	}
	return "[]"
}

// extractToolName returns the tool name from a tools/call request, or "".
func extractToolName(msg jsonrpcMessage) string {
	if len(msg.Params) == 0 {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(msg.Params, &params); err == nil {
		return params.Name
	}
	return ""
}

// extractContent pulls scannable text from a JSON-RPC message.
func extractContent(msg jsonrpcMessage) string {
	// For tool calls, extract the arguments
	if msg.Method == "tools/call" && len(msg.Params) > 0 {
		var params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &params); err == nil {
			return params.Name + " " + string(params.Arguments)
		}
	}

	// For results, extract text content
	if len(msg.Result) > 0 {
		var result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(msg.Result, &result); err == nil {
			var texts []string
			for _, c := range result.Content {
				if c.Text != "" {
					texts = append(texts, c.Text)
				}
			}
			if len(texts) > 0 {
				return joinStrings(texts)
			}
		}
		// Fallback: scan raw result
		return string(msg.Result)
	}

	// For any params, scan the raw content
	if len(msg.Params) > 0 {
		return string(msg.Params)
	}

	return ""
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += "\n"
		}
		result += s
	}
	return result
}
