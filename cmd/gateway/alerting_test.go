package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// withAlertConfig points the gateway at the given alert targets for one test.
func withAlertConfig(t *testing.T, cfg *config.GatewayConfig) {
	t.Helper()
	currentConfigMu.Lock()
	prev := currentConfig
	currentConfig = cfg
	currentConfigMu.Unlock()
	t.Cleanup(func() {
		currentConfigMu.Lock()
		currentConfig = prev
		currentConfigMu.Unlock()
	})
}

// fastBackoff keeps retry tests from actually sleeping seconds.
func fastBackoff(t *testing.T) {
	t.Helper()
	prev := alertBackoffBase
	alertBackoffBase = time.Millisecond
	t.Cleanup(func() { alertBackoffBase = prev })
}

// The whole point of opt-in: with nothing configured, no delivery is attempted
// at all.
func TestNotifyAlertNoTargetsDoesNothing(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()

	withAlertConfig(t, &config.GatewayConfig{}) // no alert targets
	notifyAlert(alertEvent{AgentID: "web-1", Dimension: "cpu", Status: "firing"})
	time.Sleep(30 * time.Millisecond)

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("delivered %d times with no targets configured, want 0", got)
	}
}

func TestNotifyAlertWebhookPayload(t *testing.T) {
	type received struct {
		body []byte
		ct   string
	}
	ch := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- received{body: b, ct: r.Header.Get("Content-Type")}
	}))
	defer srv.Close()

	withAlertConfig(t, &config.GatewayConfig{AlertWebhookURL: srv.URL, GatewayID: "gw-1"})
	notifyAlert(alertEvent{
		AgentID: "web-1", Dimension: "cpu", Status: "firing",
		Value: 91.5, Threshold: 90, Timestamp: time.Unix(1700000000, 0),
	})

	select {
	case got := <-ch:
		if got.ct != "application/json" {
			t.Errorf("content-type: got %q, want application/json", got.ct)
		}
		var ev alertEvent
		if err := json.Unmarshal(got.body, &ev); err != nil {
			t.Fatalf("payload is not valid JSON: %v (%s)", err, got.body)
		}
		if ev.AgentID != "web-1" || ev.Dimension != "cpu" || ev.Status != "firing" {
			t.Errorf("unexpected event: %+v", ev)
		}
		if ev.Value != 91.5 || ev.Threshold != 90 {
			t.Errorf("value/threshold: got %v/%v, want 91.5/90", ev.Value, ev.Threshold)
		}
		if ev.GatewayID != "gw-1" {
			t.Errorf("gateway_id: got %q, want gw-1", ev.GatewayID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the alert")
	}
}

// Alertmanager resolves by endsAt, not by a status field - a firing alert must
// NOT carry endsAt, or Alertmanager pins it firing until that time.
func TestAlertmanagerPayloadEndsAtOnlyWhenResolved(t *testing.T) {
	tests := []struct {
		status       string
		wantEndsAtIn bool
	}{
		{"firing", false},
		{"resolved", true},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			body, err := alertmanagerPayload(alertEvent{
				AgentID: "web-1", Dimension: "cpu", Status: tc.status,
				Value: 91.5, Threshold: 90, Timestamp: time.Unix(1700000000, 0),
			})
			if err != nil {
				t.Fatal(err)
			}
			var alerts []map[string]interface{}
			if err := json.Unmarshal(body, &alerts); err != nil {
				t.Fatalf("payload is not valid JSON: %v", err)
			}
			if len(alerts) != 1 {
				t.Fatalf("got %d alerts, want 1 (Alertmanager expects an array)", len(alerts))
			}
			_, hasEndsAt := alerts[0]["endsAt"]
			if hasEndsAt != tc.wantEndsAtIn {
				t.Errorf("endsAt present = %v, want %v", hasEndsAt, tc.wantEndsAtIn)
			}
			if _, ok := alerts[0]["startsAt"]; !ok {
				t.Error("startsAt missing")
			}
			labels := alerts[0]["labels"].(map[string]interface{})
			if labels["agent_id"] != "web-1" || labels["dimension"] != "cpu" {
				t.Errorf("labels: %+v", labels)
			}
		})
	}
}

func TestAlertmanagerEndpoint(t *testing.T) {
	for _, base := range []string{"http://am:9093", "http://am:9093/"} {
		if got := alertmanagerEndpoint(base); got != "http://am:9093/api/v2/alerts" {
			t.Errorf("base %q -> %q", base, got)
		}
	}
}

// A 5xx must be retried; the delivery succeeds once the target recovers.
func TestDeliverWithRetryRetriesOn5xx(t *testing.T) {
	fastBackoff(t)
	// resetMetrics clears counters accumulated by a previous -count iteration;
	// the unique target additionally isolates this test from notifyAlert's
	// background goroutines in OTHER tests, which record asynchronously and
	// would otherwise land in a shared "webhook" key after the reset.
	resetMetrics()
	target := "TestDeliverWithRetryRetriesOn5xx"

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	deliverWithRetry(target, srv.URL, []byte(`{}`), nil, 3)

	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts: got %d, want 3 (2 failures then success)", got)
	}
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if n := alertDeliveries[alertDeliveryKey{target: target, status: "success"}]; n != 1 {
		t.Errorf("success counter: got %d, want 1", n)
	}
}

// A 4xx is a permanent rejection - retrying a malformed/unauthorized request
// just burns attempts against a target that will never accept it.
func TestDeliverWithRetryDoesNotRetryOn4xx(t *testing.T) {
	fastBackoff(t)
	// resetMetrics clears counters accumulated by a previous -count iteration;
	// the unique target additionally isolates this test from notifyAlert's
	// background goroutines in OTHER tests, which record asynchronously and
	// would otherwise land in a shared "webhook" key after the reset.
	resetMetrics()
	target := "TestDeliverWithRetryDoesNotRetryOn4xx"

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	deliverWithRetry(target, srv.URL, []byte(`{}`), nil, 3)

	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("attempts: got %d, want 1 (4xx must not be retried)", got)
	}
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if n := alertDeliveries[alertDeliveryKey{target: target, status: "error"}]; n != 1 {
		t.Errorf("error counter: got %d, want 1", n)
	}
}

// 429 is the exception to the 4xx rule: it means "slow down", not "never".
func TestDeliverWithRetryRetriesOn429(t *testing.T) {
	fastBackoff(t)
	resetMetrics()
	target := "TestDeliverWithRetryRetriesOn429"

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	deliverWithRetry(target, srv.URL, []byte(`{}`), nil, 3)

	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Errorf("attempts: got %d, want 2 (429 must be retried)", got)
	}
}

// Retries are bounded: a target that never recovers must not loop forever.
func TestDeliverWithRetryGivesUpAfterRetries(t *testing.T) {
	fastBackoff(t)
	// resetMetrics clears counters accumulated by a previous -count iteration;
	// the unique target additionally isolates this test from notifyAlert's
	// background goroutines in OTHER tests, which record asynchronously and
	// would otherwise land in a shared "webhook" key after the reset.
	resetMetrics()
	target := "TestDeliverWithRetryGivesUpAfterRetries"

	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	deliverWithRetry(target, srv.URL, []byte(`{}`), nil, 2)

	// 1 initial + 2 retries
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("attempts: got %d, want 3 (1 initial + 2 retries)", got)
	}
	metricsMu.Lock()
	defer metricsMu.Unlock()
	if n := alertDeliveries[alertDeliveryKey{target: target, status: "error"}]; n != 1 {
		t.Errorf("error counter: got %d, want 1", n)
	}
}

// Both targets configured => both get the alert.
func TestNotifyAlertDeliversToBothTargets(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	var webhookHits, amHits int32
	var amPath string
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookHits, 1)
		wg.Done()
	}))
	defer webhook.Close()
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&amHits, 1)
		amPath = r.URL.Path
		wg.Done()
	}))
	defer am.Close()

	withAlertConfig(t, &config.GatewayConfig{AlertWebhookURL: webhook.URL, AlertmanagerURL: am.URL})
	notifyAlert(alertEvent{AgentID: "web-1", Dimension: "cpu", Status: "firing", Timestamp: time.Now()})

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("not both targets hit: webhook=%d am=%d", atomic.LoadInt32(&webhookHits), atomic.LoadInt32(&amHits))
	}
	if amPath != "/api/v2/alerts" {
		t.Errorf("alertmanager path: got %q, want /api/v2/alerts", amPath)
	}
}

// #127: an on-call system needs a token, and before this the only way to pass
// one was to put it in the URL — where it then lands in config, logs and errors.
func TestNotifyAlertSendsAuthHeaders(t *testing.T) {
	got := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Clone()
	}))
	defer srv.Close()

	withAlertConfig(t, &config.GatewayConfig{
		AlertWebhookURL:     srv.URL,
		AlertWebhookHeaders: map[string]string{"Authorization": "Bearer SECRET-TOKEN", "X-Routing-Key": "oncall"},
	})
	notifyAlert(alertEvent{AgentID: "web-1", Dimension: "cpu", Status: "firing", Timestamp: time.Now()})

	select {
	case h := <-got:
		if h.Get("Authorization") != "Bearer SECRET-TOKEN" {
			t.Errorf("Authorization = %q, want Bearer SECRET-TOKEN", h.Get("Authorization"))
		}
		if h.Get("X-Routing-Key") != "oncall" {
			t.Errorf("X-Routing-Key = %q, want oncall", h.Get("X-Routing-Key"))
		}
		if h.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type clobbered: %q", h.Get("Content-Type"))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook never received the alert")
	}
}

// A credential in the URL must never reach the log. Existing configs still
// carry them, since URL-smuggling was the only auth option before #127.
func TestRedactURLStripsCredentials(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://user:pass@hooks.example.com/x", "https://hooks.example.com/x"},
		{"https://hooks.example.com/x?token=SECRET", "https://hooks.example.com/x"},
		{"https://hooks.example.com/x", "https://hooks.example.com/x"},
	}
	for _, tc := range tests {
		if got := redactURL(tc.in); got != tc.want {
			t.Errorf("redactURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := redactURL("https://u:p@h/x?token=SECRET"); strings.Contains(got, "SECRET") || strings.Contains(got, "p@") {
		t.Errorf("credential survived redaction: %q", got)
	}
}

// Go's *url.Error stringifies with the full URL, so the raw error must never be
// logged verbatim.
func TestRedactDeliveryErrorHidesURLCredentials(t *testing.T) {
	raw := "https://hooks.example.com/x?token=SUPERSECRET"
	err := &url.Error{Op: "Post", URL: raw, Err: errors.New("connection refused")}
	msg := redactDeliveryError(err, raw)

	if strings.Contains(msg, "SUPERSECRET") {
		t.Errorf("token leaked into the log line: %s", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("redaction destroyed the useful part of the error: %s", msg)
	}
}
