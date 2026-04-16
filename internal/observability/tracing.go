// Package observability wires OpenTelemetry tracing into oktsec.
//
// The goal is propagation, not vendor integration: when a request enters the
// proxy, gateway or any other HTTP surface, the same trace context should
// flow through every downstream call (scanner, audit store, webhook, backend
// MCP server) so an operator can correlate a single agent message across
// replicas and services.
//
// Default exporter is stdout JSON — zero new infra required to turn it on.
// Config switches to OTLP (gRPC) for production telemetry systems like
// Tempo, Jaeger, Honeycomb, etc. Keeping the exporter pluggable behind a
// small interface means the rest of the codebase doesn't know which
// backend is in play.
package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TracingConfig is the declarative config consumed by Init.
type TracingConfig struct {
	Enabled     bool
	ServiceName string
	// Exporter is one of: "stdout" (default), "none".
	// OTLP is intentionally deferred — adding it pulls in a heavy gRPC
	// dependency that many oktsec deployments don't need. When someone
	// actually uses an OTLP collector we'll add it behind an optional
	// build tag.
	Exporter string
	// SamplingRatio is in [0, 1]. 1.0 means every span is recorded, 0.0
	// turns tracing off while leaving context propagation intact.
	SamplingRatio float64
}

// Shutdown is returned by Init. Callers should defer it in main() so any
// buffered spans are flushed before the process exits.
type Shutdown func(context.Context) error

var (
	initMu       sync.Mutex
	initialized  bool
	noopShutdown Shutdown = func(context.Context) error { return nil }
)

// Init configures the global TracerProvider + context propagator. Calling
// Init twice is a no-op on subsequent calls — useful for tests that run
// against a shared process.
//
// Always returns a valid Shutdown, even on error, so callers can defer it
// unconditionally.
func Init(cfg TracingConfig, logger *slog.Logger) (Shutdown, error) {
	initMu.Lock()
	defer initMu.Unlock()
	if initialized {
		return noopShutdown, nil
	}

	if logger == nil {
		logger = slog.Default()
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "oktsec"
	}
	if !cfg.Enabled {
		// Propagation only, no recorder. Traces entering via
		// traceparent headers still flow through downstream services.
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		initialized = true
		logger.Info("tracing: disabled (propagation-only)")
		return noopShutdown, nil
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(clampRatio(cfg.SamplingRatio)))

	exp, err := buildExporter(cfg.Exporter)
	if err != nil {
		return noopShutdown, fmt.Errorf("tracing: build exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(buildResource(cfg.ServiceName)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	initialized = true
	logger.Info("tracing: enabled", "exporter", cfg.Exporter, "sampling", cfg.SamplingRatio)

	return func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}, nil
}

// Tracer returns a tracer under the oktsec namespace. Safe to call before
// Init — you'll just get spans that go to the noop provider.
func Tracer(name string) trace.Tracer {
	return otel.GetTracerProvider().Tracer("oktsec/" + name)
}

// Propagator exposes the active propagator so non-HTTP callers (stdio
// proxy, MCP tool invocations) can inject/extract context themselves.
func Propagator() propagation.TextMapPropagator {
	return otel.GetTextMapPropagator()
}

func buildExporter(name string) (sdktrace.SpanExporter, error) {
	switch name {
	case "", "stdout":
		return stdouttrace.New(
			stdouttrace.WithWriter(os.Stderr),
			stdouttrace.WithPrettyPrint(),
		)
	case "none":
		return noopExporter{}, nil
	default:
		return nil, fmt.Errorf("unknown exporter %q (supported: stdout, none)", name)
	}
}

func clampRatio(r float64) float64 {
	switch {
	case r <= 0:
		return 0
	case r >= 1:
		return 1
	default:
		return r
	}
}
