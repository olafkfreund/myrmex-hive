package command

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/olafkfreund/mcp-os-agent/pkg/config"
)

// ExecuteCommand validates and runs an approved command with a timeout
func ExecuteCommand(name string, args []string, allowedCommands []config.AllowedCommand) (string, error) {
	// 1. Validate if the command name is allowed
	var matchedCmd *config.AllowedCommand
	for _, cmd := range allowedCommands {
		if cmd.Name == name {
			matchedCmd = &cmd
			break
		}
	}

	if matchedCmd == nil {
		return "", fmt.Errorf("command %q is not in the approved allowlist", name)
	}

	// 2. Validate arguments against regex
	fullArgsStr := strings.Join(args, " ")
	if matchedCmd.ArgsRegex != "" {
		re, err := regexp.Compile(matchedCmd.ArgsRegex)
		if err != nil {
			return "", fmt.Errorf("invalid regex pattern in allowlist config for command %q: %w", name, err)
		}

		if !re.MatchString(fullArgsStr) {
			return "", fmt.Errorf("arguments %q do not match the approved pattern %q", fullArgsStr, matchedCmd.ArgsRegex)
		}
	} else if len(args) > 0 {
		return "", fmt.Errorf("command %q does not allow arguments", name)
	}

	// 3. Execute the command securely with a 30s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run command directly (no shell invocation, preventing injection)
	cmd := exec.CommandContext(ctx, name, args...)

	// Capture both stdout and stderr
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return string(output), fmt.Errorf("command timed out: %w", err)
		}
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}
