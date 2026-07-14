package main

// OpenTelemetry tracing (issue #98).
//
// Opt-in via tracing_enabled. When it is off, initTracing installs nothing:
// otel's global tracer provider stays the default no-op, so startSpan returns
// a non-recording span, no exporter goroutines exist and no network calls are
// made. The instrumentation call sites therefore cost a few nanoseconds each
// and need no `if tracingEnabled` guards.
//
// Unlike the Prometheus exposition (hand-written, see metrics.go), this uses
// the real OTel SDK: tracing has genuinely subtle parts - context propagation,
// sampling, batching, retry - where reimplementing the spec would trade a small
// vendor tree for bugs we own. See CLAUDE.md on the dependency footprint.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// tracerName identifies this instrumentation scope in the exported spans.
const tracerName = "github.com/olafkfreund/myrmex-hive/cmd/gateway"

// tracerProvider is retained solely so shutdownTracing can flush it on exit.
// nil when tracing is disabled.
var tracerProvider *sdktrace.TracerProvider

// tracer returns the global tracer. When tracing is disabled this is otel's
// no-op provider, so callers never need to check.
func tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// initTracing installs a global tracer provider and OTLP/HTTP exporter when
// cfg.TracingEnabled is set. It returns nil (and installs nothing) otherwise,
// so an unconfigured gateway behaves exactly as before.
func initTracing(ctx context.Context, cfg *config.GatewayConfig) error {
	if cfg == nil || !cfg.TracingEnabled {
		return nil
	}

	endpoint := cfg.OTLPEndpoint
	if endpoint == "" {
		endpoint = "localhost:4318"
	}
	serviceName := cfg.TraceServiceName
	if serviceName == "" {
		serviceName = "myrmex-gateway"
	}
	// 0 means "unset" in JSON, and a gateway's tool-call rate is low enough
	// that sampling everything is the useful default. A negative ratio is
	// treated as never-sample by ParentBased/TraceIDRatioBased anyway.
	ratio := cfg.TraceSampleRatio
	if ratio == 0 {
		ratio = 1.0
	}

	opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
	if cfg.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	if len(cfg.OTLPHeaders) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.OTLPHeaders))
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return fmt.Errorf("otlp exporter: %w", err)
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(version),
	}
	if cfg.GatewayID != "" {
		// Lets a trace be attributed to one gateway in an HA peer mesh.
		attrs = append(attrs, attribute.String("myrmex.gateway_id", cfg.GatewayID))
	}
	// The semconv version above MUST match the one sdkresource.Default() uses
	// (see vendor/go.opentelemetry.io/otel/sdk/resource/builtin.go), or Merge
	// fails with "conflicting Schema URL" and tracing silently never starts.
	// TestInitTracingEnabledBuildsResource pins this so an SDK upgrade breaks
	// the build rather than production.
	res, err := sdkresource.Merge(sdkresource.Default(), sdkresource.NewWithAttributes(semconv.SchemaURL, attrs...))
	if err != nil {
		return fmt.Errorf("otel resource: %w", err)
	}

	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		// ParentBased so a sampling decision made upstream (e.g. by the peer
		// gateway that forwarded to us) is honored rather than re-rolled,
		// which would produce broken half-sampled traces.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
	)
	otel.SetTracerProvider(tracerProvider)
	// W3C traceparent/tracestate + baggage: the format peers and collectors
	// expect.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	// The SDK logs exporter failures through this; route them to our log
	// rather than the default stderr handler so a dead collector is visible
	// but never fatal.
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		log.Printf("[TRACE] exporter error: %v", err)
	}))

	log.Printf("OpenTelemetry tracing enabled: endpoint=%s service=%s sample_ratio=%g", endpoint, serviceName, ratio)
	return nil
}

// shutdownTracing flushes any buffered spans. Called on the graceful-shutdown
// path: the batcher holds spans in memory, so exiting without this drops the
// spans for whatever was happening at shutdown - exactly the ones worth having
// when debugging a crash-on-exit.
func shutdownTracing() {
	if tracerProvider == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tracerProvider.Shutdown(ctx); err != nil {
		log.Printf("[TRACE] shutdown: %v", err)
	}
}

// startSpan begins a span. Safe to call unconditionally: with tracing off the
// global provider is a no-op and this allocates nothing meaningful.
func startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer().Start(ctx, name, trace.WithAttributes(attrs...))
}

// endSpanWithError closes span, recording err as the span status when non-nil.
// Centralized so every call site reports failures the same way.
func endSpanWithError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

// endSpanWithRPCResult closes span based on a JSON-RPC response: Error non-nil
// means the call failed. Mirrors how instrumentToolCall classifies the same
// response for /metrics, so traces and metrics agree on what "error" means.
func endSpanWithRPCResult(span trace.Span, resp JsonRpcResponse) {
	if resp.Error != nil {
		errBytes, _ := json.Marshal(resp.Error)
		span.SetStatus(codes.Error, string(errBytes))
		span.SetAttributes(attribute.Bool("myrmex.rpc.error", true))
	}
	span.End()
}

// traceToolCall wraps a ResponseSender so span is closed when the response is
// sent, whatever path produced it — the same reason instrumentToolCall wraps
// send for /metrics rather than deferring: the upstream-MCP branch dispatches
// a goroutine and returns immediately, so a deferred End() would report a ~0s
// span. sync.Once guards against a path that sends twice.
func traceToolCall(send ResponseSender, span trace.Span) ResponseSender {
	var once sync.Once
	return func(resp JsonRpcResponse) {
		once.Do(func() { endSpanWithRPCResult(span, resp) })
		send(resp)
	}
}

// traceHeaderCarrier injects the current span context into outbound HTTP
// headers as W3C traceparent, so a peer gateway continues this trace rather
// than starting a disconnected one.
func injectTraceContext(ctx context.Context, headers map[string][]string) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(headers))
}

// extractTraceContext pulls a W3C traceparent out of inbound HTTP headers,
// returning a context whose spans become children of the caller's span.
func extractTraceContext(ctx context.Context, headers map[string][]string) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(headers))
}
