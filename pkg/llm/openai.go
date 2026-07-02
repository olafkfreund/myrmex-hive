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
		// No client-level Timeout: the deadline is applied per-request via
		// context in doGenerate so that GenerateOptions.Timeout can
		// override it in either direction (see defaultRequestTimeout).
		client: &http.Client{},
	}
}

// Generate produces a completion for the given prompt via the
// /chat/completions endpoint, sending it as a single user message.
func (c *OpenAIClient) Generate(prompt string) (string, error) {
	return c.GenerateWithOptions(prompt, GenerateOptions{})
}

// GenerateWithOptions produces a completion for prompt via the
// /chat/completions endpoint, honoring a per-call model override, timeout,
// and bounded retry with backoff. See GenerateOptions for details on each
// field.
func (c *OpenAIClient) GenerateWithOptions(prompt string, opts GenerateOptions) (string, error) {
	model := c.Model
	if opts.Model != "" {
		model = opts.Model
	}

	timeout := defaultRequestTimeout
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	reqBody := OpenAIChatRequest{
		Model: model,
		Messages: []OpenAIChatMessage{
			{Role: "user", Content: prompt},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OpenAI-compatible request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryBackoff(attempt - 1))
		}

		result, retryable, err := c.doGenerate(jsonData, timeout)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retryable {
			return "", err
		}
	}

	return "", lastErr
}

// doGenerate performs a single OpenAI-compatible /chat/completions request
// within timeout. The second return value reports whether a non-nil error
// is transient and worth retrying (transport failures and HTTP 429/5xx
// responses).
func (c *OpenAIClient) doGenerate(jsonData []byte, timeout time.Duration) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", false, fmt.Errorf("failed to build OpenAI-compatible request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", true, fmt.Errorf("failed to contact OpenAI-compatible LLM backend: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", isRetryableStatus(resp.StatusCode), fmt.Errorf("OpenAI-compatible LLM backend returned non-200 status: %d", resp.StatusCode)
	}

	var chatResp OpenAIChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", false, fmt.Errorf("failed to decode OpenAI-compatible LLM response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", false, fmt.Errorf("OpenAI-compatible LLM backend returned no choices")
	}

	return chatResp.Choices[0].Message.Content, false, nil
}

// Name identifies this engine for logging/diagnostics purposes, e.g.
// "openai:gpt-4o".
func (c *OpenAIClient) Name() string {
	return "openai:" + c.Model
}
