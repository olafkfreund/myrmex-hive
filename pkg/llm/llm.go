package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type Client struct {
	OllamaURL string
	Model     string
	client    *http.Client
}

func NewClient(url, model string) *Client {
	if url == "" {
		url = "http://localhost:11434"
	}
	if model == "" {
		model = "gemma2:2b"
	}
	return &Client{
		OllamaURL: url,
		Model:     model,
		// No client-level Timeout: the deadline is applied per-request via
		// context in doGenerate so that GenerateOptions.Timeout can
		// override it in either direction (see defaultRequestTimeout).
		client: &http.Client{},
	}
}

func (c *Client) Generate(prompt string) (string, error) {
	return c.GenerateWithOptions(prompt, GenerateOptions{})
}

// GenerateWithOptions produces a completion for prompt, honoring a per-call
// model override, timeout, and bounded retry with backoff. See
// GenerateOptions for details on each field.
func (c *Client) GenerateWithOptions(prompt string, opts GenerateOptions) (string, error) {
	model := c.Model
	if opts.Model != "" {
		model = opts.Model
	}

	timeout := defaultRequestTimeout
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}

	reqBody := OllamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
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

// doGenerate performs a single Ollama /api/generate request within timeout.
// The second return value reports whether a non-nil error is transient and
// worth retrying (transport failures and HTTP 429/5xx responses).
func (c *Client) doGenerate(jsonData []byte, timeout time.Duration) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/generate", c.OllamaURL), bytes.NewBuffer(jsonData))
	if err != nil {
		return "", false, fmt.Errorf("failed to build Ollama request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", true, fmt.Errorf("failed to contact local LLM (Ollama): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", isRetryableStatus(resp.StatusCode), fmt.Errorf("local LLM returned non-200 status: %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", false, fmt.Errorf("failed to decode LLM response: %w", err)
	}

	return ollamaResp.Response, false, nil
}

// Name identifies this engine for logging/diagnostics purposes. It reports
// the backend type and configured model, e.g. "ollama:gemma2:2b".
func (c *Client) Name() string {
	return "ollama:" + c.Model
}

func (c *Client) HumanizeLog(logContent string) (string, error) {
	prompt := fmt.Sprintf(`You are a system administrator assistant. Please explain the following system log entry or event log in plain English, highlighting any warnings, security issues, or operational concerns. Keep the output concise (1-3 sentences) and professional.

Log Content:
%s

Humanized Explanation:`, logContent)

	return c.Generate(prompt)
}
