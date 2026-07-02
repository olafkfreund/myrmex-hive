package command

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/olafkfreund/mcp-os-agent/pkg/config"
)

// validateCommand enforces the allowlist and argument policy for a requested
// command and resolves it to an absolute executable path. It performs every
// safety check ExecuteCommand relies on WITHOUT running anything, so it can be
// shared by the real execution path and the dry-run path.
func validateCommand(name string, args []string, allowedCommands []config.AllowedCommand) (execPath string, err error) {
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

	// 3. Harden against silent PATH substitution: if the allowlisted command name
	// is not already an absolute path, resolve it to one via LookPath. Fail if it
	// cannot be resolved.
	execPath = name
	if !filepath.IsAbs(execPath) {
		resolved, lookErr := exec.LookPath(name)
		if lookErr != nil {
			return "", fmt.Errorf("failed to resolve command %q on PATH: %w", name, lookErr)
		}
		execPath = resolved
	}

	return execPath, nil
}

// DryRun validates a command exactly as ExecuteCommand would (allowlist,
// argument regex, absolute-path resolution) but does NOT execute it. It returns
// a human-readable description of the command that WOULD run, so operators can
// preview an action before committing to it.
func DryRun(name string, args []string, allowedCommands []config.AllowedCommand) (string, error) {
	execPath, err := validateCommand(name, args, allowedCommands)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[dry-run] approved; would execute: %s %s", execPath, strings.Join(args, " ")), nil
}

// ExecuteCommand validates and runs an approved command with a timeout
func ExecuteCommand(name string, args []string, allowedCommands []config.AllowedCommand) (string, error) {
	execPath, err := validateCommand(name, args, allowedCommands)
	if err != nil {
		return "", err
	}

	// Execute the command securely with a 30s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run command directly (no shell invocation, preventing injection)
	cmd := exec.CommandContext(ctx, execPath, args...)

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
