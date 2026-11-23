package app

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nadi-agent/internal/logdedupe"
	"nadi-agent/internal/nginxlogs"
	"nadi-agent/internal/spool"
	"nadi-agent/internal/state"
)

func TestNginxErrorLogFingerprintIsStableAndContentSensitive(t *testing.T) {
	timestamp := time.Date(2026, 11, 23, 8, 0, 0, 0, time.UTC)
	first := nginxlogs.Entry{
		Timestamp: timestamp,
		Severity:  "error",
		Message:   "upstream connection failed",
		Source:    "nginx",
	}
	second := first
	third := first
	third.Message = "upstream timeout"

	if nginxErrorLogFingerprint(first) != nginxErrorLogFingerprint(second) {
		t.Fatal("identical Nginx error log entries must have stable fingerprints")
	}
	if nginxErrorLogFingerprint(first) == nginxErrorLogFingerprint(third) {
		t.Fatal("different Nginx error log messages must have different fingerprints")
	}
}


func TestCollectNginxErrorLogsPersistsBeforeAdvancingCursorAndSurvivesRestart(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "error.log")
	cursorPath := filepath.Join(directory, "cursor.json")
	logContent := "2026/11/23 08:00:00 [error] 123#123: first failure\n" +
		"2026/11/23 08:00:01 [warn] 123#123: second warning\n"
	if err := os.WriteFile(logPath, []byte(logContent), 0600); err != nil {
		t.Fatal(err)
	}

	telemetrySpool, err := spool.Open(filepath.Join(directory, "spool"), 1024*1024, 100)
	if err != nil {
		t.Fatal(err)
	}
	dedupe, err := logdedupe.Open(filepath.Join(directory, "dedupe"))
	if err != nil {
		t.Fatal(err)
	}
	collector, err := nginxlogs.NewDurableCollector(logPath, cursorPath, nginxlogs.DefaultMaximumBytes, 1)
	if err != nil {
		t.Fatal(err)
	}

	agent := &App{
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		telemetrySpool: telemetrySpool,
		logDedupe:     dedupe,
		nginxErrorLogs: collector,
	}
	identity := state.State{
		CentralServerID: "server-1",
		CentralAgentID:  "agent-1",
	}

	agent.collectNginxErrorLogs(identity)

	collector, err = nginxlogs.NewDurableCollector(logPath, cursorPath, nginxlogs.DefaultMaximumBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	agent.nginxErrorLogs = collector
	agent.collectNginxErrorLogs(identity)
	agent.collectNginxErrorLogs(identity)

	records, err := telemetrySpool.ReadBatch(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected two distinct Nginx spool events after restart, got %d", len(records))
	}
	if records[0].EventType != "nginx_error_logs" || records[1].EventType != "nginx_error_logs" {
		t.Fatalf("unexpected server spool event types: %q, %q", records[0].EventType, records[1].EventType)
	}
	if records[0].Payload.NginxErrorLogs[0].Message != "first failure" ||
		records[1].Payload.NginxErrorLogs[0].Message != "second warning" {
		t.Fatalf("Nginx cursor skipped or repeated an entry: %#v", records)
	}
}
