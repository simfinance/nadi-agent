package app

import (
	"testing"
	"time"

	"nadi-agent/internal/nginxlogs"
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
