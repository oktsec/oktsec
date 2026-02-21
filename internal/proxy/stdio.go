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
	"time"

	"github.com/google/uuid"
	"github.com/oktsec/oktsec/internal/audit"
	"github.com/oktsec/oktsec/internal/engine"
)

// StdioProxy wraps an MCP server process, intercepting stdio JSON-RPC messages.
type StdioProxy struct {
	agent   string
	scanner *engine.Scanner
	audit   *audit.Store
	logger  *slog.Logger
}

// NewStdioProxy creates a proxy for intercepting MCP stdio communication.
func NewStdioProxy(agent string, scanner *engine.Scanner, auditStore *audit.Store, logger *slog.Logger) *StdioProxy {
	return &StdioProxy{
		agent:   agent,
		scanner: scanner,
		audit:   auditStore,
		logger:  logger,
	}
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

	// Client → oktsec → Server (stdin)
	go func() {
		errCh <- p.proxyStream(os.Stdin, childIn, "client", p.agent)
		_ = childIn.Close()
	}()

	// Server → oktsec → Client (stdout)
	go func() {
		errCh <- p.proxyStream(childOut, os.Stdout, p.agent, "client")
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

func (p *StdioProxy) proxyStream(src io.Reader, dst io.Writer, from, to string) error {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := scanner.Bytes()

		p.inspectMessage(line, from, to)

		// Forward line as-is (transparent proxy)
		if _, err := dst.Write(line); err != nil {
			return err
		}
		if _, err := dst.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) inspectMessage(line []byte, from, to string) {
	start := time.Now()
	msgID := uuid.New().String()

	var msg jsonrpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		// Not valid JSON-RPC, pass through silently
		return
	}

	// Extract content to scan
	content := extractContent(msg)
	if content == "" {
		// Structural messages (notifications, results with no scannable content)
		return
	}

	// Scan content
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	outcome, err := p.scanner.ScanContent(ctx, content)
	if err != nil {
		p.logger.Error("scan failed", "error", err, "method", msg.Method)
		return
	}

	status := "delivered"
	decision := "allow"
	switch outcome.Verdict {
	case engine.VerdictBlock:
		status = "blocked"
		decision = "content_blocked"
	case engine.VerdictQuarantine:
		status = "quarantined"
		decision = "content_quarantined"
	case engine.VerdictFlag:
		decision = "content_flagged"
	}

	rulesJSON := "[]"
	if len(outcome.Findings) > 0 {
		if b, err := json.Marshal(outcome.Findings); err == nil {
			rulesJSON = string(b)
		}
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
