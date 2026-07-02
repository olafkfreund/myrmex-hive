package llm

import "errors"

// Engine is the minimal, backend-agnostic contract the Gateway needs from a
// language model. It decouples callers (e.g. the Gemma orchestration loop)
// from any single provider so that additional backends (llama.cpp, vLLM,
// OpenAI-compatible servers, etc.) can be added without touching call sites.
//
// The existing Ollama-backed *Client already satisfies this interface; see
// the compile-time assertion below.
type Engine interface {
	// Generate produces a completion for the given prompt.
	Generate(prompt string) (string, error)

	// Name identifies the engine (backend + model) for logging/diagnostics.
	Name() string
}

// Compile-time assertion that *Client implements Engine.
var _ Engine = (*Client)(nil)

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
func (Disabled) Generate(prompt string) (string, error) {
	return "", errors.New("no LLM engine is configured")
}

// Name reports the disabled engine's identifier.
func (Disabled) Name() string {
	return "disabled"
}

// EngineConfig selects and configures an Engine implementation.
//
// Provider selects the backend:
//   - ""  or "ollama": local Ollama server (default)
//   - "disabled":       no LLM backend; Generate always errors
//
// URL and Model are backend-specific; for Ollama they map directly to
// NewClient's url and model parameters.
type EngineConfig struct {
	Provider string
	URL      string
	Model    string
}

// NewEngine constructs an Engine from cfg. Unknown providers currently fall
// back to Ollama to preserve existing behavior while additional backends are
// implemented.
//
// TODO: llama.cpp, vLLM, openai-compatible backends (#53)
func NewEngine(cfg EngineConfig) Engine {
	switch cfg.Provider {
	case "disabled":
		return NewDisabled()
	case "", "ollama":
		return NewClient(cfg.URL, cfg.Model)
	default:
		// TODO: llama.cpp, vLLM, openai-compatible backends (#53)
		return NewClient(cfg.URL, cfg.Model)
	}
}
