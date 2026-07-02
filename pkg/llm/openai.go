package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OpenAIChatMessage is a single message in an OpenAI Chat Completions request.
type OpenAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatRequest is the request body for POST /v1/chat/completions.
type OpenAIChatRequest struct {
	Model    string              `json:"model"`
	Messages []OpenAIChatMessage `json:"messages"`
}

// OpenAIChatResponse is the subset of the Chat Completions response body we
// care about.
type OpenAIChatResponse struct {
	Choices []struct {
		Message OpenAIChatMessage `json:"message"`
	} `json:"choices"`
}

// OpenAIClient talks to any backend exposing an OpenAI-compatible
// /v1/chat/completions endpoint. This single implementation serves OpenAI
// itself, vLLM, and llama.cpp's server, since all three speak the same wire
// protocol.
type OpenAIClient struct {
	BaseURL string
	Model   string
	APIKey  string
	client  *http.Client
}

// Compile-time assertion that *OpenAIClient implements Engine.
var _ Engine = (*OpenAIClient)(nil)

// NewOpenAIClient constructs an OpenAIClient. baseURL defaults to
// "http://localhost:8000/v1" (a common local vLLM/llama.cpp default) when
// empty. apiKey is optional; when set it is sent as a Bearer token.
func NewOpenAIClient(baseURL, model, apiKey string) *OpenAIClient {
	if baseURL == "" {
		baseURL = "http://localhost:8000/v1"
	}
	return &OpenAIClient{
		BaseURL: baseURL,
		Model:   model,
		APIKey:  apiKey,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Generate produces a completion for the given prompt via the
// /chat/completions endpoint, sending it as a single user message.
func (c *OpenAIClient) Generate(prompt string) (string, error) {
	reqBody := OpenAIChatRequest{
		Model: c.Model,
		Messages: []OpenAIChatMessage{
			{Role: "user", Content: prompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OpenAI-compatible request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to build OpenAI-compatible request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to contact OpenAI-compatible LLM backend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OpenAI-compatible LLM backend returned non-200 status: %d", resp.StatusCode)
	}

	var chatResp OpenAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("failed to decode OpenAI-compatible LLM response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("OpenAI-compatible LLM backend returned no choices")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// Name identifies this engine for logging/diagnostics purposes, e.g.
// "openai:gpt-4o".
func (c *OpenAIClient) Name() string {
	return "openai:" + c.Model
}
