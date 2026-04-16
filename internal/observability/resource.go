package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// buildResource stamps every span with service identity so multi-tenant
// OTEL backends can filter oktsec traces out of the firehose.
func buildResource(serviceName string) *resource.Resource {
	return resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(serviceName),
		attribute.String("component", "oktsec"),
	)
}

// noopExporter is used when the operator wants propagation without
// recording. It's not quite the same as disabling tracing: spans still
// get IDs and flow through contexts, which is enough for correlating
// logs across services.
type noopExporter struct{}

func (noopExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error { return nil }
func (noopExporter) Shutdown(context.Context) error                             { return nil }
