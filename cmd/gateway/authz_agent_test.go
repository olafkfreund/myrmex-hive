package main

import (
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// authorizeAgentAccess is the agent/tag half of authorizeToolCall, reused by
// the fleet drill-down (#109). It must agree with authorizeToolCall on which
// agents a scope may see — that is the whole reason it was extracted rather
// than copied.
func TestAuthorizeAgentAccess(t *testing.T) {
	tags := map[string][]string{"web-1": {"prod"}, "db-1": {"prod", "db"}, "lab-1": {"lab"}}

	tests := []struct {
		name    string
		scope   *config.TokenScope
		agentID string
		wantOK  bool
	}{
		{"nil scope is unrestricted", nil, "web-1", true},
		{"empty scope is unrestricted", &config.TokenScope{}, "web-1", true},
		{"agent in Agents", &config.TokenScope{Agents: []string{"web-1"}}, "web-1", true},
		{"agent NOT in Agents", &config.TokenScope{Agents: []string{"web-1"}}, "db-1", false},
		{"agent via Tags", &config.TokenScope{Tags: []string{"db"}}, "db-1", true},
		{"agent tag not matched", &config.TokenScope{Tags: []string{"db"}}, "web-1", false},
		{"gateway is never agent-scoped", &config.TokenScope{Agents: []string{"web-1"}}, "gateway", true},
		// The reason for the extraction: a Tools restriction must NOT block a
		// read. authorizeToolCall(tool="") would fail this.
		{"Tools restriction does not block a read", &config.TokenScope{Agents: []string{"web-1"}, Tools: []string{"get_metrics"}}, "web-1", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := authorizeAgentAccess(tc.scope, tags, tc.agentID)
			if (err == nil) != tc.wantOK {
				t.Errorf("authorizeAgentAccess(%v, %q) err=%v, wantOK=%v", tc.scope, tc.agentID, err, tc.wantOK)
			}
		})
	}
}

// The extraction must not have changed authorizeToolCall's agent decisions.
func TestAuthorizeAgentAccessAgreesWithToolCall(t *testing.T) {
	tags := map[string][]string{"web-1": {"prod"}, "db-1": {"db"}}
	scopes := []*config.TokenScope{
		nil,
		{},
		{Agents: []string{"web-1"}},
		{Tags: []string{"db"}},
		{Agents: []string{"web-1"}, Tags: []string{"db"}},
	}
	for _, scope := range scopes {
		for _, agent := range []string{"web-1", "db-1", "other", "gateway"} {
			agentErr := authorizeAgentAccess(scope, tags, agent)
			// tool="" with no Tools restriction isolates the agent decision.
			toolErr := authorizeToolCall(scope, tags, agent, "")
			if (agentErr == nil) != (toolErr == nil) {
				t.Errorf("disagree for scope=%v agent=%q: agentAccess=%v toolCall=%v", scope, agent, agentErr, toolErr)
			}
		}
	}
}
