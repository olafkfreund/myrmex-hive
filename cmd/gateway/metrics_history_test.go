package main

import (
	"encoding/json"
	"testing"
	"time"
)

// TestAttachMetricsHistoryIfAvailable covers the get_metrics enrichment added
// for #7: the gateway already collects a metricsHistory ring buffer via the
// opt-in metricsPoller, but previously never surfaced it back through the
// get_metrics tool call itself. This is a no-op when history hasn't been
// collected, and otherwise adds a "history" field without disturbing any
// existing field.
func TestAttachMetricsHistoryIfAvailable(t *testing.T) {
	// Shaped as extractToolResultText expects it in production: a real
	// JsonRpcResponse.Result arrives here already decoded from JSON bytes
	// (via cli.Call), so "content" is []interface{}, not a concrete slice.
	sample := func(cpu float64) JsonRpcResponse {
		return JsonRpcResponse{
			Result: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": `{"cpu_usage_percent":` + jsonNum(cpu) + `}`},
				},
			},
		}
	}

	t.Run("fewer than two samples is a no-op", func(t *testing.T) {
		resp := sample(12.5)
		want := resp
		got := attachMetricsHistoryIfAvailable(resp, nil)
		if !jsonEqual(t, got, want) {
			t.Errorf("expected unchanged response for empty history, got %+v", got)
		}

		got = attachMetricsHistoryIfAvailable(resp, []MetricSample{{Timestamp: time.Now(), Raw: json.RawMessage(`{"cpu_usage_percent":12.5}`)}})
		if !jsonEqual(t, got, want) {
			t.Errorf("expected unchanged response for single-sample history, got %+v", got)
		}
	})

	t.Run("two or more samples attach a history field and preserve current fields", func(t *testing.T) {
		resp := sample(42)
		history := []MetricSample{
			{Timestamp: time.Unix(1000, 0).UTC(), Raw: json.RawMessage(`{"cpu_usage_percent":10}`)},
			{Timestamp: time.Unix(1060, 0).UTC(), Raw: json.RawMessage(`{"cpu_usage_percent":42}`)},
		}

		got := attachMetricsHistoryIfAvailable(resp, history)

		text, ok := extractToolResultText(got.Result)
		if !ok {
			t.Fatalf("expected extractable text from enriched response, got %+v", got.Result)
		}

		var decoded struct {
			CPUUsagePercent float64        `json:"cpu_usage_percent"`
			History         []MetricSample `json:"history"`
		}
		if err := json.Unmarshal([]byte(text), &decoded); err != nil {
			t.Fatalf("enriched text is not valid JSON: %v (%s)", err, text)
		}

		if decoded.CPUUsagePercent != 42 {
			t.Errorf("cpu_usage_percent: got %v, want 42 (must survive enrichment untouched)", decoded.CPUUsagePercent)
		}
		if len(decoded.History) != 2 {
			t.Fatalf("history: got %d entries, want 2", len(decoded.History))
		}
		if string(decoded.History[0].Raw) != `{"cpu_usage_percent":10}` {
			t.Errorf("history[0].Raw: got %s, want the first sample verbatim", decoded.History[0].Raw)
		}
		if string(decoded.History[1].Raw) != `{"cpu_usage_percent":42}` {
			t.Errorf("history[1].Raw: got %s, want the second sample verbatim", decoded.History[1].Raw)
		}
	})

	t.Run("non-JSON tool result is left alone", func(t *testing.T) {
		resp := JsonRpcResponse{
			Result: map[string]interface{}{
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "not json"},
				},
			},
		}
		history := []MetricSample{
			{Timestamp: time.Now(), Raw: json.RawMessage(`{"cpu_usage_percent":1}`)},
			{Timestamp: time.Now(), Raw: json.RawMessage(`{"cpu_usage_percent":2}`)},
		}
		got := attachMetricsHistoryIfAvailable(resp, history)
		if !jsonEqual(t, got, resp) {
			t.Errorf("expected unchanged response for non-JSON tool text, got %+v", got)
		}
	})
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func jsonEqual(t *testing.T, a, b interface{}) bool {
	t.Helper()
	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	return string(ab) == string(bb)
}
