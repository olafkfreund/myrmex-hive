package llm

import (
	"errors"
	"net/http"
	"time"
)

// Engine is the minimal, backend-agnostic contract the Gateway needs from a
// language model. It decouples callers (e.g. the Gemma orchestration loop)
// from any single provider so that additional backends (llama.cpp, vLLM,
// OpenAI-compatible servers, etc.) can be added without touching call sites.
//
// The existing Ollama-backed *Client already satisfies this interface; see
// the compile-time assertion below.
type Engine interface {
	// Generate produces a completion for the given prompt using the
	// engine's configured defaults. It is equivalent to calling
	// GenerateWithOptions(prompt, GenerateOptions{}).
	Generate(prompt string) (string, error)

	// GenerateWithOptions produces a completion for the given prompt,
	// allowing a per-call override of model, timeout, and retry behavior
	// via opts. A zero-value GenerateOptions behaves identically to
	// Generate.
	GenerateWithOptions(prompt string, opts GenerateOptions) (string, error)

	// Name identifies the engine (backend + model) for logging/diagnostics.
	Name() string
}

// defaultRequestTimeout is the per-request deadline used when a caller does
// not supply GenerateOptions.Timeout. It is applied purely via context (see
// Client.doGenerate / OpenAIClient.doGenerate) so that a caller-supplied
// GenerateOptions.Timeout can freely override it in either direction.
const defaultRequestTimeout = 60 * time.Second

// GenerateOptions customizes a single Generate call. All fields are
// optional; a zero value uses the engine's configured defaults and behaves
// identically to Generate.
type GenerateOptions struct {
	// Model overrides the engine's configured model for this call only.
	// The engine's own default model is left unchanged for subsequent
	// calls.
	Model string

	// Timeout overrides the per-request context timeout for this call
	// only. When zero, the engine's default request timeout is used.
	Timeout time.Duration

	// MaxRetries is the number of additional attempts made after an
	// initial transient failure (transport errors, HTTP 429, or HTTP 5xx)
	// before giving up. A value of 0 (the default) means no retries.
	// Non-retryable errors (other 4xx statuses, decode errors) return
	// immediately without consuming a retry.
	MaxRetries int
}

// Compile-time assertions that the built-in backends implement Engine.
var (
	_ Engine = (*Client)(nil)
	_ Engine = (*OpenAIClient)(nil)
	_ Engine = Disabled{}
)

// Disabled is a no-op Engine used when no LLM backend is configured. Calling
// Generate always returns an error so that callers fail fast with a clear,
// actionable message instead of nil-pointer panics or silent no-ops.
type Disabled struct{}

// NewDisabled returns an Engine that rejects all Generate calls. Useful as a
// safe default when LLM features are turned off.
func NewDisabled() Engine {
	return Disabled{}
}

// Generate always fails: no backend is configured.
func (d Disabled) Generate(prompt string) (string, error) {
	return d.GenerateWithOptions(prompt, GenerateOptions{})
}

// GenerateWithOptions always fails: no backend is configured. opts is
// ignored since there is nothing to configure.
func (Disabled) GenerateWithOptions(prompt string, opts GenerateOptions) (string, error) {
	return "", errors.New("no LLM engine is configured")
}

// Name reports the disabled engine's identifier.
func (Disabled) Name() string {
	return "disabled"
}

// isRetryableStatus reports whether an HTTP status code returned by an LLM
// backend indicates a transient failure worth retrying: HTTP 429 (rate
// limited) or any 5xx server error.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// retryBackoff returns the delay to wait before retry attempt n, where n is
// 0 for the first retry (i.e. after the initial attempt fails), 1 for the
// second retry, and so on. Delays double each attempt starting at 200ms
// (200ms, 400ms, 800ms, ...).
func retryBackoff(n int) time.Duration {
	return 200 * time.Millisecond << n
}

// EngineConfig selects and configures an Engine implementation.
//
// Provider selects the backend:
//   - ""  or "ollama":                             local Ollama server (default)
//   - "openai", "vllm", "llamacpp", "openai-compatible": any backend exposing
//     an OpenAI-compatible /v1/chat/completions endpoint (OpenAI itself,
//     vLLM, or llama.cpp's server)
//   - "disabled":                                   no LLM backend; Generate always errors
//
// URL and Model are backend-specific; for Ollama they map directly to
// NewClient's url and model parameters. APIKey is only used by the
// OpenAI-compatible backend, where it is sent as a Bearer token when set.
type EngineConfig struct {
	Provider string
	URL      string
	Model    string
	APIKey   string
}

// NewEngine constructs an Engine from cfg. Unknown providers currently fall
// back to Ollama to preserve existing behavior.
func NewEngine(cfg EngineConfig) Engine {
	switch cfg.Provider {
	case "disabled":
		return NewDisabled()
	case "openai", "vllm", "llamacpp", "openai-compatible":
		return NewOpenAIClient(cfg.URL, cfg.Model, cfg.APIKey)
	case "", "ollama":
		return NewClient(cfg.URL, cfg.Model)
	default:
		// Unknown provider: default to Ollama.
		return NewClient(cfg.URL, cfg.Model)
	}
}
