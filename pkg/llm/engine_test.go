package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestClientGenerateWithOptionsModelOverride verifies that
// GenerateOptions.Model overrides the request model for a single call
// without mutating the Client's configured default model.
func TestClientGenerateWithOptionsModelOverride(t *testing.T) {
	const defaultModel = "gemma2:2b"
	const overrideModel = "llama3:8b"

	var gotReq OllamaRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OllamaResponse{Response: "ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, defaultModel)

	got, err := client.GenerateWithOptions("hello", GenerateOptions{Model: overrideModel})
	if err != nil {
		t.Fatalf("GenerateWithOptions returned unexpected error: %v", err)
	}
	if got != "ok" {
		t.Errorf("GenerateWithOptions() = %q, want %q", got, "ok")
	}
	if gotReq.Model != overrideModel {
		t.Errorf("request model = %q, want override %q", gotReq.Model, overrideModel)
	}
	if client.Model != defaultModel {
		t.Errorf("client.Model = %q, want unchanged default %q", client.Model, defaultModel)
	}

	// A subsequent call without an override must fall back to the
	// client's own default model.
	gotReq = OllamaRequest{}
	if _, err := client.Generate("hello again"); err != nil {
		t.Fatalf("Generate returned unexpected error: %v", err)
	}
	if gotReq.Model != defaultModel {
		t.Errorf("request model = %q, want default %q", gotReq.Model, defaultModel)
	}
}

// TestClientGenerateWithOptionsRetrySucceeds verifies that a transient 500
// response is retried and a subsequent 200 response succeeds within
// MaxRetries.
func TestClientGenerateWithOptionsRetrySucceeds(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OllamaResponse{Response: "recovered"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "model")

	got, err := client.GenerateWithOptions("hello", GenerateOptions{MaxRetries: 2})
	if err != nil {
		t.Fatalf("GenerateWithOptions returned unexpected error: %v", err)
	}
	if got != "recovered" {
		t.Errorf("GenerateWithOptions() = %q, want %q", got, "recovered")
	}
	if n := atomic.LoadInt32(&attempts); n != 2 {
		t.Errorf("attempts = %d, want 2 (one failure + one success)", n)
	}
}

// TestClientGenerateWithOptionsNoRetryByDefault verifies that MaxRetries=0
// (the zero value) makes exactly one attempt and surfaces the error
// immediately, matching Generate's existing behavior.
func TestClientGenerateWithOptionsNoRetryByDefault(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "model")

	if _, err := client.GenerateWithOptions("hello", GenerateOptions{}); err == nil {
		t.Fatal("expected an error for a 500 response with MaxRetries=0, got nil")
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("attempts = %d, want exactly 1 (no retries)", n)
	}
}

// TestClientGenerateWithOptionsNonRetryableStatus verifies that a
// non-retryable 4xx status (other than 429) returns immediately even when
// MaxRetries is set, without consuming any retry attempts.
func TestClientGenerateWithOptionsNonRetryableStatus(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := NewClient(server.URL, "model")

	if _, err := client.GenerateWithOptions("hello", GenerateOptions{MaxRetries: 3}); err == nil {
		t.Fatal("expected an error for a 400 response, got nil")
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("attempts = %d, want exactly 1 (400 is not retryable)", n)
	}
}

// TestClientGenerateWithOptionsTimeoutHonored verifies that
// GenerateOptions.Timeout is applied to the request: a short timeout
// against a slow backend must fail with a deadline-exceeded style error.
func TestClientGenerateWithOptionsTimeoutHonored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(OllamaResponse{Response: "too slow"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "model")

	start := time.Now()
	_, err := client.GenerateWithOptions("hello", GenerateOptions{Timeout: 10 * time.Millisecond})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed >= 100*time.Millisecond {
		t.Errorf("request took %v, expected it to be cut short by the 10ms timeout", elapsed)
	}
}

// TestOpenAIClientGenerateWithOptionsModelOverride mirrors the Ollama model
// override test for the OpenAI-compatible backend.
func TestOpenAIClientGenerateWithOptionsModelOverride(t *testing.T) {
	const defaultModel = "gpt-4o-mini"
	const overrideModel = "gpt-4o"

	var gotReq OpenAIChatRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		resp := OpenAIChatResponse{
			Choices: []struct {
				Message OpenAIChatMessage `json:"message"`
			}{
				{Message: OpenAIChatMessage{Role: "assistant", Content: "ok"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, defaultModel, "")

	if _, err := client.GenerateWithOptions("hello", GenerateOptions{Model: overrideModel}); err != nil {
		t.Fatalf("GenerateWithOptions returned unexpected error: %v", err)
	}
	if gotReq.Model != overrideModel {
		t.Errorf("request model = %q, want override %q", gotReq.Model, overrideModel)
	}
	if client.Model != defaultModel {
		t.Errorf("client.Model = %q, want unchanged default %q", client.Model, defaultModel)
	}
}

// TestOpenAIClientGenerateWithOptionsRetrySucceeds mirrors the Ollama retry
// test for the OpenAI-compatible backend, using a 429 to also exercise the
// rate-limit retry path.
func TestOpenAIClientGenerateWithOptionsRetrySucceeds(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		resp := OpenAIChatResponse{
			Choices: []struct {
				Message OpenAIChatMessage `json:"message"`
			}{
				{Message: OpenAIChatMessage{Role: "assistant", Content: "recovered"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "model", "")

	got, err := client.GenerateWithOptions("hello", GenerateOptions{MaxRetries: 2})
	if err != nil {
		t.Fatalf("GenerateWithOptions returned unexpected error: %v", err)
	}
	if got != "recovered" {
		t.Errorf("GenerateWithOptions() = %q, want %q", got, "recovered")
	}
	if n := atomic.LoadInt32(&attempts); n != 2 {
		t.Errorf("attempts = %d, want 2 (one 429 + one success)", n)
	}
}

// TestOpenAIClientGenerateWithOptionsNoRetryByDefault mirrors the Ollama
// no-retry-by-default test for the OpenAI-compatible backend.
func TestOpenAIClientGenerateWithOptionsNoRetryByDefault(t *testing.T) {
	var attempts int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "model", "")

	if _, err := client.GenerateWithOptions("hello", GenerateOptions{}); err == nil {
		t.Fatal("expected an error for a 500 response with MaxRetries=0, got nil")
	}
	if n := atomic.LoadInt32(&attempts); n != 1 {
		t.Errorf("attempts = %d, want exactly 1 (no retries)", n)
	}
}

// TestOpenAIClientGenerateWithOptionsTimeoutHonored mirrors the Ollama
// timeout test for the OpenAI-compatible backend.
func TestOpenAIClientGenerateWithOptionsTimeoutHonored(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := OpenAIChatResponse{
			Choices: []struct {
				Message OpenAIChatMessage `json:"message"`
			}{
				{Message: OpenAIChatMessage{Role: "assistant", Content: "too slow"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "model", "")

	start := time.Now()
	_, err := client.GenerateWithOptions("hello", GenerateOptions{Timeout: 10 * time.Millisecond})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed >= 100*time.Millisecond {
		t.Errorf("request took %v, expected it to be cut short by the 10ms timeout", elapsed)
	}
}

// TestDisabledGenerateWithOptions verifies Disabled.GenerateWithOptions
// always errors, matching Disabled.Generate.
func TestDisabledGenerateWithOptions(t *testing.T) {
	d := Disabled{}
	if _, err := d.GenerateWithOptions("hello", GenerateOptions{Model: "whatever", MaxRetries: 5}); err == nil {
		t.Fatal("expected Disabled.GenerateWithOptions to always error, got nil")
	}
}
