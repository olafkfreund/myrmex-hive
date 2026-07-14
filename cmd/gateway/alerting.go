package main

// Outbound alert delivery (issue #100).
//
// The gateway's threshold alerts (see evaluateAlertDimension) previously went
// only to the log and the signed audit trail. This routes them to external
// on-call systems: a generic JSON webhook and/or a Prometheus Alertmanager.
//
// Opt-in and backward-compatible: with neither alert_webhook_url nor
// alertmanager_url configured, notifyAlert returns before doing any work, so
// no goroutines, no network calls, no behavior change.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// alertEvent is one threshold transition: a breach onset ("firing") or a
// recovery ("resolved") for a single agent/dimension pair.
type alertEvent struct {
	AgentID   string    `json:"agent_id"`
	Dimension string    `json:"dimension"` // "cpu" | "mem" | "disk"
	Status    string    `json:"status"`    // "firing" | "resolved"
	Value     float64   `json:"value"`
	Threshold float64   `json:"threshold"`
	Timestamp time.Time `json:"timestamp"`
	GatewayID string    `json:"gateway_id,omitempty"`
}

// alertHTTPClient is a package-level client so tests can point delivery at an
// httptest server's transport. The timeout bounds a single attempt; retries
// are handled by deliverWithRetry.
var alertHTTPClient = &http.Client{Timeout: 10 * time.Second}

// alertBackoffBase is the first retry delay, doubling per attempt. Overridden
// in tests to keep them fast.
var alertBackoffBase = time.Second

// notifyAlert delivers ev to every configured target. It returns immediately;
// delivery runs in the background so a slow or dead webhook can never stall
// the metrics poller that produced the alert.
func notifyAlert(ev alertEvent) {
	currentConfigMu.RLock()
	var webhookURL, amURL, gatewayID string
	retries := 0
	if currentConfig != nil {
		webhookURL = currentConfig.AlertWebhookURL
		amURL = currentConfig.AlertmanagerURL
		gatewayID = currentConfig.GatewayID
		retries = currentConfig.AlertDeliveryRetries
	}
	currentConfigMu.RUnlock()

	// The common case: nothing configured, nothing to do.
	if webhookURL == "" && amURL == "" {
		return
	}
	if retries == 0 {
		retries = 3
	} else if retries < 0 {
		retries = 0
	}
	ev.GatewayID = gatewayID

	if webhookURL != "" {
		body, err := json.Marshal(ev)
		if err != nil {
			// Can't happen for this struct, but never let a marshal error
			// take down the poller goroutine.
			log.Printf("[ALERT] webhook payload marshal failed: %v", err)
		} else {
			go deliverWithRetry("webhook", webhookURL, body, retries)
		}
	}

	if amURL != "" {
		body, err := alertmanagerPayload(ev)
		if err != nil {
			log.Printf("[ALERT] alertmanager payload marshal failed: %v", err)
		} else {
			go deliverWithRetry("alertmanager", alertmanagerEndpoint(amURL), body, retries)
		}
	}
}

// alertmanagerEndpoint appends Alertmanager's v2 alerts path to a base URL,
// tolerating a trailing slash. Configuring the base URL (rather than the full
// path) keeps the config field consistent with how Alertmanager is normally
// addressed.
func alertmanagerEndpoint(base string) string {
	return strings.TrimSuffix(base, "/") + "/api/v2/alerts"
}

// alertmanagerPayload renders ev in Alertmanager's POST /api/v2/alerts shape.
//
// Alertmanager has no explicit "resolved" flag: an alert is resolved by giving
// it an endsAt in the past/now. Firing alerts deliberately omit endsAt, which
// lets Alertmanager apply its own resolve_timeout - setting a future endsAt
// would instead pin the alert firing until that time even if it recovers.
func alertmanagerPayload(ev alertEvent) ([]byte, error) {
	alert := map[string]interface{}{
		"labels": map[string]string{
			"alertname":  "MyrmexThresholdBreach",
			"agent_id":   ev.AgentID,
			"dimension":  ev.Dimension,
			"severity":   "warning",
			"gateway_id": ev.GatewayID,
		},
		"annotations": map[string]string{
			"summary":   fmt.Sprintf("%s %s usage %.2f%% exceeded threshold %.2f%%", ev.AgentID, ev.Dimension, ev.Value, ev.Threshold),
			"value":     fmt.Sprintf("%.2f", ev.Value),
			"threshold": fmt.Sprintf("%.2f", ev.Threshold),
		},
		"startsAt": ev.Timestamp.UTC().Format(time.RFC3339),
	}
	if ev.Status == "resolved" {
		alert["endsAt"] = ev.Timestamp.UTC().Format(time.RFC3339)
	}
	return json.Marshal([]interface{}{alert})
}

// deliverWithRetry POSTs body to url, retrying with exponential backoff on
// transport errors and 5xx/429 responses. A 4xx (other than 429) is a
// permanent rejection - retrying a malformed or unauthorized request just
// wastes attempts - so it fails fast.
func deliverWithRetry(target, url string, body []byte, retries int) {
	backoff := alertBackoffBase
	for attempt := 0; ; attempt++ {
		status, err := postAlert(url, body)
		if err == nil && status < 300 {
			recordAlertDelivery(target, "success")
			return
		}

		permanent := err == nil && status >= 400 && status < 500 && status != http.StatusTooManyRequests
		if permanent {
			log.Printf("[ALERT] %s delivery rejected (HTTP %d), not retrying: %s", target, status, url)
			recordAlertDelivery(target, "error")
			return
		}
		if attempt >= retries {
			if err != nil {
				log.Printf("[ALERT] %s delivery failed after %d attempt(s): %v", target, attempt+1, err)
			} else {
				log.Printf("[ALERT] %s delivery failed after %d attempt(s): HTTP %d", target, attempt+1, status)
			}
			recordAlertDelivery(target, "error")
			return
		}
		time.Sleep(backoff)
		backoff *= 2
	}
}

func postAlert(url string, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := alertHTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
