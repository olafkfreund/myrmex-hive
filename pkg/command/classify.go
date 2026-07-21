package command

import "strings"

// Audit statuses for a tool call. "denied" is deliberately distinct from
// "failure": a denial means the allowlist refused the call and nothing ran,
// which is a security event, while a failure means an approved command ran and
// went wrong, which is an operational one. Flattening both to "success" is
// what #174 was about — in an incident review "an operator ran this" and "the
// allowlist stopped them" are opposite facts, and a run of denials is exactly
// the signal that someone is probing the boundary.
const (
	StatusSuccess = "success"
	StatusDenied  = "denied"
	StatusFailure = "failure"
)

// ResultFailurePrefix is the marker the agent puts in front of any tool result
// that did not complete cleanly. It lives here, next to the errors it wraps,
// so the agent that writes it and the Gateway that classifies it cannot drift
// apart — cmd/agent references this constant rather than repeating the string.
//
// Classification is gated on this prefix, which matters: a SUCCESSFUL
// `read_logs` whose output happens to contain the words "command failed:"
// must not be audited as a failure. Only text the agent itself marked as
// unsuccessful is ever classified.
const ResultFailurePrefix = "Command failed/rejected:"

// deniedMarkers are substrings unique to validateCommand's refusals — the
// cases where the allowlist rejected the call and NOTHING was executed.
//
// These are matched as text rather than as errors on purpose: the Gateway
// classifies a tool result that has already crossed the SSH tunnel as a
// string, so the error value is long gone by then. Classifying gateway-side,
// rather than having the agent set a new flag, is also what makes this work
// against agents that are already deployed and will never be upgraded.
//
// TestClassifyCoversEveryRealError generates these messages from the real code
// paths, so rewording an error without updating this list fails the build.
var deniedMarkers = []string{
	"is not in the approved allowlist",
	"do not match the approved pattern",
	"does not allow arguments",
	"invalid regex pattern in allowlist config",
}

// failureMarkers are substrings unique to a command that PASSED the allowlist
// and then failed to run or exited non-zero.
var failureMarkers = []string{
	"command failed:",
	"command timed out:",
	"failed to resolve command",
}

// ClassifyResult maps the text of a tool result back to an audit status.
//
// It returns StatusDenied when the allowlist refused the call, StatusFailure
// when an approved command ran and failed, and StatusSuccess otherwise.
// Denial is checked first: a refusal is the more important fact, and the agent
// wraps both kinds in the same ResultFailurePrefix, so order is what separates
// them.
//
// Unrecognised failures classify as StatusFailure rather than StatusSuccess:
// the agent has already said this call did not succeed, so when in doubt the
// audit log should not claim it did.
func ClassifyResult(text string) string {
	if !strings.Contains(text, ResultFailurePrefix) {
		return StatusSuccess
	}
	for _, m := range deniedMarkers {
		if strings.Contains(text, m) {
			return StatusDenied
		}
	}
	for _, m := range failureMarkers {
		if strings.Contains(text, m) {
			return StatusFailure
		}
	}
	return StatusFailure
}
