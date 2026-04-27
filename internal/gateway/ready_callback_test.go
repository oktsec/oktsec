package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SetReadyCallback fires exactly once after the listener has been
// successfully bound. The dashboard uses this hook to flip
// "Configured Port" to "Listening on" only when the port is truly
// live. If we fired the callback any earlier (e.g., during NewGateway)
// the dashboard would mark the port live before the bind, and a
// bind failure would leave the label stuck claiming a listener that
// never existed.
func TestGateway_SetReadyCallback_FiresAfterBind(t *testing.T) {
	cfg := defaultGatewayConfig()
	gw := newTestGateway(t, cfg, map[string]*mcp.Server{"echo": echoServer()})

	// Buffered so the callback never blocks if Start beats the
	// receiver to the channel.
	ready := make(chan int, 1)
	gw.SetReadyCallback(func() {
		// cfg.Gateway.Port has been mutated to the actual listener
		// port by the time this fires — capture it for the assertion
		// so the test proves the contract end-to-end.
		ready <- gw.cfg.Gateway.Port
	})

	startErr := make(chan error, 1)
	go func() { startErr <- gw.Start(context.Background()) }()

	select {
	case actualPort := <-ready:
		if actualPort == 0 {
			t.Errorf("ready callback fired but cfg.Gateway.Port is still 0; bind did not update it")
		}
	case err := <-startErr:
		t.Fatalf("Start returned before ready callback: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("ready callback did not fire within 2s")
	}

	// Closing the listener directly is the cheapest way to unblock
	// Serve without touching the rest of the Gateway lifecycle. We
	// avoid calling gw.Shutdown here because that also closes
	// scanner + audit, and t.Cleanup (registered by newTestGateway)
	// will close those a second time. Any non-nil return from Serve
	// after a forced listener close is acceptable for this test —
	// the contract we are pinning is "callback fires after bind",
	// not the post-shutdown error shape.
	if gw.ln != nil {
		_ = gw.ln.Close()
	}
	select {
	case <-startErr:
		// Serve returned. Specific error value is not part of this
		// test's contract.
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within 2s after listener close")
	}
}
