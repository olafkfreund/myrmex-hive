package main

// Scheduled recurring orchestration (issue #6): opt-in via
// GatewayConfig.ScheduledTasks. Each task periodically re-runs the same
// ask_gemma orchestration loop used for on-demand asks, and routes the
// resulting summary through notifyAlert - the same webhook/Alertmanager
// delivery path threshold alerts already use.
//
// Nothing here changes on-demand orchestration: runScheduledTask is a thin
// adapter around executeGemmaOrchestration that captures its final response
// instead of writing it back over a live MCP connection.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// startScheduledTasks launches one ticker goroutine per configured task with
// a valid interval. Called once at gateway startup; a no-op (starts no
// goroutines) when ScheduledTasks is empty.
func startScheduledTasks(cfg *config.GatewayConfig) {
	for _, task := range cfg.ScheduledTasks {
		if task.IntervalSeconds <= 0 {
			log.Printf("[SCHEDULE] task %q: interval_seconds must be > 0, skipping", task.Name)
			continue
		}
		go runScheduledTaskLoop(task)
	}
}

// ponytail: plain time.Ticker, no cron parsing - add cron expressions only
// if a fixed interval stops being enough.
func runScheduledTaskLoop(task config.ScheduledTask) {
	ticker := time.NewTicker(time.Duration(task.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		runScheduledTask(context.Background(), task)
	}
}

// runScheduledTask runs one orchestration pass for task and emits the
// resulting summary via notifyAlert. Split out from runScheduledTaskLoop so
// a single tick can be tested without driving a real ticker.
func runScheduledTask(ctx context.Context, task config.ScheduledTask) {
	cli := getAgent(task.AgentID)
	if cli == nil {
		log.Printf("[SCHEDULE] task %q: agent %s not connected, skipping this tick", task.Name, task.AgentID)
		return
	}
	if !isLLMEnabled(llmEngine) {
		log.Printf("[SCHEDULE] task %q: LLM engine disabled, skipping", task.Name)
		return
	}

	var final JsonRpcResponse
	send := func(resp JsonRpcResponse) { final = resp }
	reqID := fmt.Sprintf("schedule-%s-%d", task.Name, time.Now().UnixNano())
	executeGemmaOrchestration(ctx, task.AgentID, cli, task.Prompt, false, reqID, send)

	// orchestrationResultText already knows how to render either an error or
	// the first content block (finalizeOrchestration always puts the summary
	// first, the raw execution log second) - reuse it rather than re-parsing.
	summary, _ := orchestrationResultText(final)
	if summary == "" {
		return
	}

	notifyAlert(alertEvent{
		AgentID:   task.AgentID,
		Dimension: "scheduled:" + task.Name,
		Status:    "firing",
		Timestamp: time.Now(),
		Message:   summary,
	})
}
