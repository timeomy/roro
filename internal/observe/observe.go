// Package observe exports Tollgate decisions as OpenTelemetry spans and
// metrics. Telemetry never carries tool arguments or results; only names,
// decisions, reason codes, and ids.
package observe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

const scope = "github.com/timeomy/tollgate"

// Telemetry emits spans and metrics for tool calls.
type Telemetry struct {
	tracer    trace.Tracer
	decisions metric.Int64Counter
	duration  metric.Float64Histogram
	shutdown  func(context.Context) error
}

// Config selects the exporter. An empty Endpoint disables export.
type Config struct {
	Endpoint    string // host:port of an OTLP/HTTP collector, e.g. localhost:4318
	Insecure    bool
	ServiceName string
	Version     string
}

// Setup creates OTLP/HTTP exporters, or no-op telemetry if disabled.
func Setup(ctx context.Context, cfg Config) (*Telemetry, error) {
	if cfg.Endpoint == "" {
		return New(tracenoop.NewTracerProvider(), metricnoop.NewMeterProvider(), nil), nil
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.Version),
	)
	topts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(cfg.Endpoint)}
	mopts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(cfg.Endpoint)}
	if cfg.Insecure {
		topts = append(topts, otlptracehttp.WithInsecure())
		mopts = append(mopts, otlpmetrichttp.WithInsecure())
	}
	texp, err := otlptracehttp.New(ctx, topts...)
	if err != nil {
		return nil, fmt.Errorf("observe: trace exporter: %w", err)
	}
	mexp, err := otlpmetrichttp.New(ctx, mopts...)
	if err != nil {
		return nil, fmt.Errorf("observe: metric exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(texp), sdktrace.WithResource(res))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewPeriodicReader(mexp)), sdkmetric.WithResource(res))
	shutdown := func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}
	return New(tp, mp, shutdown), nil
}

// New builds Telemetry from providers (tests pass in-memory recorders).
func New(tp trace.TracerProvider, mp metric.MeterProvider, shutdown func(context.Context) error) *Telemetry {
	meter := mp.Meter(scope)
	decisions, _ := meter.Int64Counter(MetricDecisions,
		metric.WithDescription("Tool-call decisions made by Tollgate"))
	duration, _ := meter.Float64Histogram(MetricServerOperationDuration, metric.WithUnit("s"),
		metric.WithDescription("Duration of MCP tools/call handling through Tollgate"),
		metric.WithExplicitBucketBoundaries(0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30, 60, 120, 300))
	if shutdown == nil {
		shutdown = func(context.Context) error { return nil }
	}
	return &Telemetry{tracer: tp.Tracer(scope), decisions: decisions, duration: duration, shutdown: shutdown}
}

// Shutdown flushes exporters.
func (t *Telemetry) Shutdown(ctx context.Context) error { return t.shutdown(ctx) }

// CallInfo identifies a tool call.
type CallInfo struct {
	Tool, Agent, Server, RequestID, Transport, SessionID string
}

// CallSpan tracks one tool call.
type CallSpan struct {
	t        *Telemetry
	span     trace.Span
	start    time.Time
	tool     string
	decision string
	reason   string
}

// StartToolCall starts the span for a tools/call request.
func (t *Telemetry) StartToolCall(ctx context.Context, c CallInfo) (context.Context, *CallSpan) {
	attrs := []attribute.KeyValue{
		attribute.String(AttrMCPMethodName, MethodToolsCall),
		attribute.String(AttrGenAIOperationName, OperationExecuteTool),
		attribute.String(AttrGenAIToolName, c.Tool),
		attribute.String(AttrGenAIAgentName, c.Agent),
		attribute.String(AttrServer, c.Server),
		attribute.String(AttrNetworkTransport, c.Transport),
	}
	if c.RequestID != "" {
		attrs = append(attrs, attribute.String(AttrJSONRPCRequestID, c.RequestID))
	}
	if c.SessionID != "" {
		attrs = append(attrs, attribute.String(AttrMCPSessionID, c.SessionID))
	}
	ctx, span := t.tracer.Start(ctx, MethodToolsCall+" "+c.Tool,
		trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attrs...))
	return ctx, &CallSpan{t: t, span: span, start: time.Now(), tool: c.Tool}
}

// Decide records the policy decision on the span and in the counter.
func (s *CallSpan) Decide(ctx context.Context, decision, reason string, policyIDs []string, approvalID string) {
	s.decision, s.reason = decision, reason
	attrs := []attribute.KeyValue{
		attribute.String(AttrDecision, decision),
		attribute.String(AttrReason, reason),
	}
	if len(policyIDs) > 0 {
		attrs = append(attrs, attribute.String(AttrPolicyIDs, strings.Join(policyIDs, ",")))
	}
	if approvalID != "" {
		attrs = append(attrs, attribute.String(AttrApprovalID, approvalID))
	}
	s.span.SetAttributes(attrs...)
	s.t.decisions.Add(ctx, 1, metric.WithAttributes(
		attribute.String(AttrDecision, decision),
		attribute.String(AttrReason, reason),
		attribute.String(AttrGenAIToolName, s.tool),
	))
}

// End finishes the span. errorType is "" on success, ErrorTypeToolError for
// an isError result, or "tollgate.<reason>" for a blocked call.
func (s *CallSpan) End(ctx context.Context, errorType, message string) {
	if errorType != "" {
		s.span.SetAttributes(attribute.String(AttrErrorType, errorType))
		s.span.SetStatus(codes.Error, message)
	}
	attrs := []attribute.KeyValue{
		attribute.String(AttrMCPMethodName, MethodToolsCall),
		attribute.String(AttrGenAIToolName, s.tool),
	}
	if errorType != "" {
		attrs = append(attrs, attribute.String(AttrErrorType, errorType))
	}
	s.t.duration.Record(ctx, time.Since(s.start).Seconds(), metric.WithAttributes(attrs...))
	s.span.End()
}
