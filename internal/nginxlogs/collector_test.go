package nginxlogs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectorDisabledWithoutConfiguredPath(t *testing.T) {
	collector, err := NewCollector("", DefaultMaximumBytes, DefaultMaximumEntries)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := collector.Collect(time.Now())
	if snapshot.Status != StatusDisabled {
		t.Fatalf("expected disabled status, got %s", snapshot.Status)
	}
	if len(snapshot.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(snapshot.Entries))
	}
}

func TestCollectorReturnsOnlyRedactedErrorMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	content := strings.Join([]string{
		`2026/11/23 08:00:00 [error] 123#123: *1 connect() failed, client: 192.0.2.10, request: "GET /?token=topsecret HTTP/1.1", host: "example.org"`,
		`2026/11/23 08:00:01 [warn] 123#123: worker process started`,
		`2026/11/23 08:00:02 [crit] 123#123: open() failed for password=hunter2`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector(path, DefaultMaximumBytes, DefaultMaximumEntries)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collector.Collect(time.Date(2026, 11, 23, 8, 1, 0, 0, time.UTC))

	if snapshot.Status != StatusAvailable {
		t.Fatalf("expected available status, got %s (%s)", snapshot.Status, snapshot.ErrorCode)
	}
	if len(snapshot.Entries) != 2 {
		t.Fatalf("expected two error entries, got %d", len(snapshot.Entries))
	}
	for _, entry := range snapshot.Entries {
		if entry.Fingerprint == "" || len(entry.Fingerprint) != 64 {
			t.Fatalf("expected SHA-256 fingerprint, got %q", entry.Fingerprint)
		}
	}
	encoded := snapshot.Entries
	for _, entry := range encoded {
		if strings.Contains(entry.Fingerprint, "topsecret") || strings.Contains(entry.Fingerprint, "hunter2") {
			t.Fatal("secret appeared in fingerprint")
		}
	}
}

func TestCollectorRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.log")
	link := filepath.Join(directory, "error.log")
	if err := os.WriteFile(target, []byte("log"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector(link, DefaultMaximumBytes, DefaultMaximumEntries)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collector.Collect(time.Now())
	if snapshot.Status != StatusUnavailable {
		t.Fatalf("expected unavailable status, got %s", snapshot.Status)
	}
}

func TestCollectorRejectsUnboundedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	if _, err := NewCollector(path, MaximumAllowedBytes+1, DefaultMaximumEntries); err == nil {
		t.Fatal("expected oversized byte limit to be rejected")
	}
	if _, err := NewCollector(path, DefaultMaximumBytes, MaximumAllowedEntries+1); err == nil {
		t.Fatal("expected oversized entry limit to be rejected")
	}
}

func TestCollectorEnforcesTailByteLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "error.log")
	content := strings.Repeat("x", 64) + "\n" +
		`2026/11/23 08:00:00 [error] 123#123: final failure` + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector(path, 48, DefaultMaximumEntries)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collector.Collect(time.Now())
	if len(snapshot.Entries) != 1 {
		t.Fatalf("expected the final bounded entry, got %d", len(snapshot.Entries))
	}
}
