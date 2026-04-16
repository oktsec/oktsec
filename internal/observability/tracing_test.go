package observability

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// TestInit_DisabledStillPropagates is the load-bearing contract: even when
// an operator turns tracing off, incoming W3C traceparent headers must flow
// through to downstream services so traces remain end-to-end-correlatable
// when another service in the chain IS recording.
func TestInit_DisabledStillPropagates(t *testing.T) {
	resetInitForTest()
	shutdown, err := Init(TracingConfig{Enabled: false}, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	prop := otel.GetTextMapPropagator()
	if prop == nil {
		t.Fatal("propagator should be installed even when tracing is disabled")
	}
	// Round-trip a traceparent through the propagator.
	inHeaders := propagation.MapCarrier{
		"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
	}
	ctx := prop.Extract(context.Background(), inHeaders)
	outHeaders := propagation.MapCarrier{}
	prop.Inject(ctx, outHeaders)
	if outHeaders["traceparent"] == "" {
		t.Fatal("traceparent must survive extract→inject even with tracing disabled")
	}
}

func TestInit_EnabledStdoutExporter(t *testing.T) {
	resetInitForTest()
	shutdown, err := Init(TracingConfig{
		Enabled:       true,
		Exporter:      "stdout",
		SamplingRatio: 1.0,
		ServiceName:   "oktsec-test",
	}, silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: a tracer can be obtained and creates spans that don't panic.
	_, span := Tracer("test").Start(context.Background(), "ping")
	span.End()
	_ = shutdown(context.Background())
}

func TestInit_UnknownExporterErrors(t *testing.T) {
	resetInitForTest()
	_, err := Init(TracingConfig{Enabled: true, Exporter: "kaboom"}, silentLogger())
	if err == nil {
		t.Fatal("unknown exporter should error")
	}
}

func TestClampRatio(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{-1, 0}, {0, 0}, {0.25, 0.25}, {1, 1}, {2, 1},
	}
	for _, tc := range cases {
		if got := clampRatio(tc.in); got != tc.want {
			t.Errorf("clampRatio(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// resetInitForTest lets each test run through Init without the sync.Once
// guard latching state from a prior test. Tests are serial within the
// package so the mutex dance is enough.
func resetInitForTest() {
	initMu.Lock()
	initialized = false
	initMu.Unlock()
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
