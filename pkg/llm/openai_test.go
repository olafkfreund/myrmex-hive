package llm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIClientGenerate(t *testing.T) {
	const wantAPIKey = "test-key-123"
	const wantModel = "gpt-4o-mini"
	const wantReply = "Hello from the mock backend."

	var gotAuthHeader string
	var gotPath string
	var gotReq OpenAIChatRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthHeader = r.Header.Get("Authorization")

		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		resp := OpenAIChatResponse{
			Choices: []struct {
				Message OpenAIChatMessage `json:"message"`
			}{
				{Message: OpenAIChatMessage{Role: "assistant", Content: wantReply}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("failed to encode mock response: %v", err)
		}
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, wantModel, wantAPIKey)

	got, err := client.Generate("say hello")
	if err != nil {
		t.Fatalf("Generate returned unexpected error: %v", err)
	}

	if got != wantReply {
		t.Errorf("Generate() = %q, want %q", got, wantReply)
	}

	if gotPath != "/chat/completions" {
		t.Errorf("request path = %q, want %q", gotPath, "/chat/completions")
	}

	if want := "Bearer " + wantAPIKey; gotAuthHeader != want {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, want)
	}

	if gotReq.Model != wantModel {
		t.Errorf("request model = %q, want %q", gotReq.Model, wantModel)
	}

	if len(gotReq.Messages) != 1 || gotReq.Messages[0].Content != "say hello" {
		t.Errorf("request messages = %+v, want single user message %q", gotReq.Messages, "say hello")
	}

	if name := client.Name(); name != "openai:"+wantModel {
		t.Errorf("Name() = %q, want %q", name, "openai:"+wantModel)
	}
}

func TestOpenAIClientGenerateNoAPIKey(t *testing.T) {
	var gotAuthHeader string
	sawHeader := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		sawHeader = gotAuthHeader != ""

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

	client := NewOpenAIClient(server.URL, "local-model", "")
	if _, err := client.Generate("ping"); err != nil {
		t.Fatalf("Generate returned unexpected error: %v", err)
	}

	if sawHeader {
		t.Errorf("expected no Authorization header when APIKey is empty, got %q", gotAuthHeader)
	}
}

func TestOpenAIClientGenerateNonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewOpenAIClient(server.URL, "model", "")
	if _, err := client.Generate("ping"); err == nil {
		t.Fatal("expected an error for non-200 response, got nil")
	}
}

func TestNewOpenAIClientDefaults(t *testing.T) {
	client := NewOpenAIClient("", "model", "")
	if client.BaseURL != "http://localhost:8000/v1" {
		t.Errorf("BaseURL = %q, want default %q", client.BaseURL, "http://localhost:8000/v1")
	}
}
