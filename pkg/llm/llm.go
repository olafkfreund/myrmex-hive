package llm

import (
	"bytes"
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
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (c *Client) Generate(prompt string) (string, error) {
	reqBody := OllamaRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := c.client.Post(
		fmt.Sprintf("%s/api/generate", c.OllamaURL),
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return "", fmt.Errorf("failed to contact local LLM (Ollama): %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("local LLM returned non-200 status: %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode LLM response: %w", err)
	}

	return ollamaResp.Response, nil
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
