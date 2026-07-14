package main

import (
	"context"
	"net/http"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// withInMemoryTracing installs a real tracer provider exporting to memory, so
// spans can be asserted on without a collector. Global otel state is restored
// afterwards.
func withInMemoryTracing(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return exp
}

// The opt-in guarantee: with tracing off, initTracing must install nothing and
// spans must be non-recording, so the instrumentation call sites cost nothing
// and no exporter goroutine exists.
func TestInitTracingDisabledInstallsNothing(t *testing.T) {
	prev := tracerProvider
	tracerProvider = nil
	t.Cleanup(func() { tracerProvider = prev })

	for _, cfg := range []*config.GatewayConfig{
		nil,
		{},                       // zero value: TracingEnabled false
		{OTLPEndpoint: "x:4318"}, // endpoint set but not enabled
	} {
		if err := initTracing(context.Background(), cfg); err != nil {
			t.Fatalf("initTracing(%v) returned error: %v", cfg, err)
		}
		if tracerProvider != nil {
			t.Fatalf("initTracing(%v) installed a tracer provider with tracing disabled", cfg)
		}
	}

	// shutdownTracing must be safe to call when nothing was installed - it is
	// on the signal path, which runs regardless of config.
	shutdownTracing()
}

// Exercises the ENABLED path, which the disabled-path test above structurally
// cannot reach.
//
// This exists because of a real bug: the semconv version imported by
// tracing.go must match the one sdkresource.Default() uses, or resource.Merge
// fails with "conflicting Schema URL", initTracing returns an error, and
// tracing SILENTLY never starts - the gateway keeps serving perfectly, just
// with no traces. It shipped past every unit test and was only caught by
// pointing a real collector at it. An SDK upgrade that bumps the schema must
// fail here instead.
//
// otlptracehttp.New does not dial eagerly, so no collector is needed.
func TestInitTracingEnabledBuildsResource(t *testing.T) {
	prev := tracerProvider
	tracerProvider = nil
	t.Cleanup(func() {
		if tracerProvider != nil {
			shutdownTracing()
		}
		tracerProvider = prev
	})

	cfg := &config.GatewayConfig{
		TracingEnabled:   true,
		OTLPEndpoint:     "localhost:4318",
		OTLPInsecure:     true,
		TraceServiceName: "myrmex-gateway-test",
		GatewayID:        "gw-1",
	}
	if err := initTracing(context.Background(), cfg); err != nil {
		t.Fatalf("initTracing with tracing enabled failed: %v\n"+
			"if this says \"conflicting Schema URL\", the semconv version in tracing.go "+
			"no longer matches the one sdkresource.Default() uses", err)
	}
	if tracerProvider == nil {
		t.Fatal("tracing enabled but no tracer provider installed")
	}
}

func TestTraceToolCallRecordsSpan(t *testing.T) {
	tests := []struct {
		name      string
		resp      JsonRpcResponse
		wantError bool
	}{
		{"success", JsonRpcResponse{JsonRpc: "2.0"}, false},
		{"error", JsonRpcResponse{JsonRpc: "2.0", Error: JsonRpcError{Code: -32603, Message: "boom"}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exp := withInMemoryTracing(t)

			_, span := startSpan(context.Background(), "mcp.tool_call")
			var sent int
			send := traceToolCall(func(JsonRpcResponse) { sent++ }, span)
			send(tc.resp)

			spans := exp.GetSpans()
			if len(spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(spans))
			}
			if sent != 1 {
				t.Errorf("underlying send called %d times, want 1", sent)
			}
			gotErr := spans[0].Status.Code == 1 // codes.Error
			if gotErr != tc.wantError {
				t.Errorf("span error status = %v, want %v (status: %+v)", gotErr, tc.wantError, spans[0].Status)
			}
		})
	}

	// A path that sends twice must not double-end the span.
	t.Run("double send ends span once", func(t *testing.T) {
		exp := withInMemoryTracing(t)
		_, span := startSpan(context.Background(), "mcp.tool_call")
		send := traceToolCall(func(JsonRpcResponse) {}, span)
		send(JsonRpcResponse{JsonRpc: "2.0"})
		send(JsonRpcResponse{JsonRpc: "2.0"})

		if n := len(exp.GetSpans()); n != 1 {
			t.Errorf("got %d spans, want 1", n)
		}
	})
}

// The cross-gateway hop: a traceparent injected by the forwarding gateway must
// be extracted by the receiving one, or the forwarded call shows up as two
// disconnected traces instead of one.
func TestTraceContextRoundTripAcrossPeers(t *testing.T) {
	withInMemoryTracing(t)

	originCtx, span := startSpan(context.Background(), "mcp.peer_forward")
	defer span.End()
	originTraceID := span.SpanContext().TraceID()

	// Origin gateway: inject into outbound headers (forwardToPeer).
	headers := http.Header{}
	injectTraceContext(originCtx, headers)

	if headers.Get("Traceparent") == "" {
		t.Fatal("no traceparent header injected")
	}

	// Peer gateway: extract from inbound headers (handleInternalCall).
	peerCtx := extractTraceContext(context.Background(), headers)
	got := trace.SpanContextFromContext(peerCtx)

	if !got.IsValid() {
		t.Fatal("extracted span context is invalid")
	}
	if got.TraceID() != originTraceID {
		t.Errorf("trace ID: peer got %s, origin had %s - the trace would be split", got.TraceID(), originTraceID)
	}
	if got.SpanID() != span.SpanContext().SpanID() {
		t.Errorf("parent span ID: got %s, want %s", got.SpanID(), span.SpanContext().SpanID())
	}
}

// With tracing off, injection must add no headers - a stray traceparent on a
// peer call would be confusing and is not free.
//
// Uses otel's noop provider EXPLICITLY rather than relying on "no provider
// installed": otel's global tracer provider delegates once SetTracerProvider
// has been called, so any earlier test in this package leaves a real provider
// reachable through the global and this assertion silently tests nothing (it
// injected a real traceparent when run after the other tracing tests).
func TestInjectIsNoOpWhenTracingDisabled(t *testing.T) {
	prevProp := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(prevProp) })

	// This is exactly what a tracing-disabled gateway has: otel's no-op tracer,
	// whose spans carry an invalid SpanContext, so the propagator emits nothing.
	ctx, span := noop.NewTracerProvider().Tracer("disabled").Start(context.Background(), "x")
	defer span.End()

	headers := http.Header{}
	injectTraceContext(ctx, headers)

	if tp := headers.Get("Traceparent"); tp != "" {
		t.Errorf("injected traceparent %q with tracing disabled, want none", tp)
	}
}
