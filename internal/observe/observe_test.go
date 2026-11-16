package observe

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestSemconvNamesMatchFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/semconv-genai-mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Attributes []string                   `json:"attributes"`
		Metrics    map[string]json.RawMessage `json:"metrics"`
	}
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	used := []string{AttrMCPMethodName, AttrMCPSessionID, AttrMCPProtocolVersion, AttrJSONRPCRequestID,
		AttrGenAIToolName, AttrGenAIOperationName, AttrGenAIAgentName, AttrNetworkTransport, AttrErrorType}
	for _, a := range used {
		if !slices.Contains(fx.Attributes, a) {
			t.Errorf("attribute %q is not in the semconv fixture; update the fixture after checking the spec", a)
		}
	}
	if _, ok := fx.Metrics[MetricServerOperationDuration]; !ok {
		t.Errorf("metric %q missing from fixture", MetricServerOperationDuration)
	}
}

func TestToolCallSpanAndMetrics(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	tel := New(tp, mp, nil)

	ctx := t.Context()
	ctx, s := tel.StartToolCall(ctx, CallInfo{Tool: "exfiltrate", Agent: "research-bot", Server: "demo", RequestID: "7", Transport: TransportPipe})
	s.Decide(ctx, "deny", "dangerous_tool_blocked", []string{"deny-dangerous-tools"}, "")
	s.End(ctx, "tollgate.dangerous_tool_blocked", "blocked")

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans = %d", len(spans))
	}
	sp := spans[0]
	if sp.Name() != "tools/call exfiltrate" {
		t.Errorf("span name = %q", sp.Name())
	}
	got := map[attribute.Key]string{}
	for _, kv := range sp.Attributes() {
		got[kv.Key] = kv.Value.Emit()
	}
	want := map[attribute.Key]string{
		AttrMCPMethodName: "tools/call", AttrGenAIOperationName: "execute_tool", AttrGenAIToolName: "exfiltrate",
		AttrGenAIAgentName: "research-bot", AttrJSONRPCRequestID: "7", AttrNetworkTransport: "pipe",
		AttrDecision: "deny", AttrReason: "dangerous_tool_blocked", AttrErrorType: "tollgate.dangerous_tool_blocked",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %s = %q, want %q", k, got[k], v)
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
		}
	}
	if !names[MetricDecisions] || !names[MetricServerOperationDuration] {
		t.Errorf("metrics = %v", names)
	}
}

func TestSetupDisabledAndOTLP(t *testing.T) {
	off, err := Setup(t.Context(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	_, s := off.StartToolCall(t.Context(), CallInfo{Tool: "x"})
	s.End(t.Context(), "", "")
	if err := off.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Exporters are created lazily; no collector needs to be running.
	on, err := Setup(t.Context(), Config{Endpoint: "127.0.0.1:1", Insecure: true, ServiceName: "tollgate", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_ = on.Shutdown(ctx) // export to a closed port fails; shutdown must still return
}
