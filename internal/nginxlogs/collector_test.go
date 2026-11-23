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

func TestCollectorEmitsCentralV11NginxErrorLogSchema(t *testing.T) {
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
	if len(snapshot.Entries) != 3 {
		t.Fatalf("expected three supported severity entries, got %d", len(snapshot.Entries))
	}

	expectedSeverities := []string{"error", "warning", "critical"}
	for index, entry := range snapshot.Entries {
		if entry.Timestamp.IsZero() || entry.Message == "" || entry.Source != "nginx" {
			t.Fatalf("entry %d does not match the Central log schema: %#v", index, entry)
		}
		if entry.Severity != expectedSeverities[index] {
			t.Fatalf("entry %d severity = %q, want %q", index, entry.Severity, expectedSeverities[index])
		}
		if strings.Contains(entry.Message, "topsecret") ||
			strings.Contains(entry.Message, "hunter2") ||
			strings.Contains(entry.Message, "192.0.2.10") ||
			strings.Contains(entry.Message, "example.org") {
			t.Fatalf("entry %d retained sensitive input: %q", index, entry.Message)
		}
		if len([]byte(entry.Message)) > MaximumMessageBytes {
			t.Fatalf("entry %d exceeds the message byte limit", index)
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

func TestCollectorRejectsSymlinkInParentPath(t *testing.T) {
	directory := t.TempDir()
	targetDirectory := filepath.Join(directory, "real")
	linkDirectory := filepath.Join(directory, "linked")
	if err := os.Mkdir(targetDirectory, 0700); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(targetDirectory, "error.log")
	if err := os.WriteFile(target, []byte("log"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector(
		filepath.Join(linkDirectory, "error.log"),
		DefaultMaximumBytes,
		DefaultMaximumEntries,
	)
	if err != nil {
		t.Fatal(err)
	}

	snapshot := collector.Collect(time.Now())
	if snapshot.Status != StatusUnavailable {
		t.Fatalf("expected unavailable status for symlink parent, got %s", snapshot.Status)
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
	content := strings.Repeat("x", 100) + "\n" +
		`2026/11/23 08:00:00 [error] 123#123: final failure` + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewCollector(path, 80, DefaultMaximumEntries)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collector.Collect(time.Now())
	if len(snapshot.Entries) != 1 {
		t.Fatalf("expected the final bounded entry, got %d", len(snapshot.Entries))
	}
}

func TestParseLineRedactsIPv6AddressesAndPreservesMessageWords(t *testing.T) {
	first, ok := parseLine("2026/11/23 08:00:00 [error] 123#123: client 2001:db8::1 returned bad gateway")
	if !ok {
		t.Fatal("expected first Nginx error line to parse")
	}

	second, ok := parseLine("2026/11/23 08:00:00 [error] 123#123: client 2001:db8::2 returned bad gateway")
	if !ok {
		t.Fatal("expected second Nginx error line to parse")
	}

	if first.Message != second.Message {
		t.Fatal("expected IPv6 addresses to be redacted from the emitted message")
	}

	third, ok := parseLine("2026/11/23 08:00:00 [error] 123#123: client 2001:db8::2 returned error gateway")
	if !ok {
		t.Fatal("expected third Nginx error line to parse")
	}

	if second.Message == third.Message {
		t.Fatal("expected ordinary message words to remain in the emitted message")
	}
}

func TestParseLineRedactsQuotedRequestsCredentialsAndCookies(t *testing.T) {
	first, ok := parseLine("2026/11/23 08:00:00 [error] 123#123: request: \"GET /?token=first HTTP/1.1\", Authorization: Bearer secret-one, Cookie: session=alpha; csrf=one")
	if !ok {
		t.Fatal("expected first Nginx error line to parse")
	}

	second, ok := parseLine("2026/11/23 08:00:00 [error] 123#123: request: \"POST /private?token=second HTTP/1.1\", Authorization: Bearer secret-two, Cookie: session=beta; csrf=two")
	if !ok {
		t.Fatal("expected second Nginx error line to parse")
	}

	if first.Message != second.Message {
		t.Fatal("expected request details, credentials, and cookies to be redacted")
	}
	for _, secret := range []string{"secret-one", "secret-two", "session=alpha", "session=beta", "token=first", "token=second"} {
		if strings.Contains(first.Message, secret) || strings.Contains(second.Message, secret) {
			t.Fatalf("sensitive value %q was retained", secret)
		}
	}
}

func TestNewCollectorRejectsNonCleanOrRelativePaths(t *testing.T) {
	paths := []string{
		"var/log/nginx/error.log",
		"/var/log/../log/nginx/error.log",
	}

	for _, path := range paths {
		if _, err := NewCollector(path, DefaultMaximumBytes, DefaultMaximumEntries); err == nil {
			t.Fatalf("expected path %q to be rejected", path)
		}
	}
}

func TestParseLineRejectsMessagesOverEightKiB(t *testing.T) {
	message := strings.Repeat("x", MaximumMessageBytes+1)
	line := "2026/11/23 08:00:00 [error] 123#123: " + message
	if _, ok := parseLine(line); ok {
		t.Fatal("expected oversized log message to be rejected")
	}
}

func TestParseLineMapsAllCentralSeverityNames(t *testing.T) {
	tests := map[string]string{
		"emerg":  "emergency",
		"alert":  "alert",
		"crit":   "critical",
		"error":  "error",
		"warn":   "warning",
		"notice": "notice",
		"info":   "info",
		"debug":  "debug",
	}

	for input, expected := range tests {
		line := "2026/11/23 08:00:00 [" + input + "] 123#123: message"
		entry, ok := parseLine(line)
		if !ok {
			t.Fatalf("expected severity %q to parse", input)
		}
		if entry.Severity != expected {
			t.Fatalf("severity %q mapped to %q, want %q", input, entry.Severity, expected)
		}
	}
}

func TestDurableCollectorReadsEntriesAcrossRestartWithoutSkipping(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "error.log")
	statePath := filepath.Join(directory, "cursor.json")
	lines := strings.Join([]string{
		"2026/11/23 08:00:00 [error] 123#123: first failure",
		"2026/11/23 08:00:01 [warn] 123#123: second warning",
		"2026/11/23 08:00:02 [crit] 123#123: third failure",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewDurableCollector(path, statePath, DefaultMaximumBytes, 1)
	if err != nil {
		t.Fatal(err)
	}

	for index, expected := range []string{"first failure", "second warning", "third failure"} {
		snapshot, cursor, err := collector.CollectWithCursor(time.Now().UTC())
		if err != nil {
			t.Fatalf("collect entry %d: %v", index, err)
		}
		if len(snapshot.Entries) != 1 || snapshot.Entries[0].Message != expected {
			t.Fatalf("entry %d = %#v, want message %q", index, snapshot.Entries, expected)
		}
		if err := collector.Commit(cursor); err != nil {
			t.Fatalf("commit cursor %d: %v", index, err)
		}

		collector, err = NewDurableCollector(path, statePath, DefaultMaximumBytes, 1)
		if err != nil {
			t.Fatalf("reopen collector %d: %v", index, err)
		}
	}
}

func TestDurableCollectorDoesNotAdvanceBeforeCommit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "error.log")
	statePath := filepath.Join(directory, "cursor.json")
	line := "2026/11/23 08:00:00 [error] 123#123: pending failure\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewDurableCollector(path, statePath, DefaultMaximumBytes, 10)
	if err != nil {
		t.Fatal(err)
	}

	first, _, err := collector.CollectWithCursor(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := collector.CollectWithCursor(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Entries) != 1 || len(second.Entries) != 1 {
		t.Fatal("uncommitted cursor must return the same pending log entry")
	}
}

func TestDurableCollectorFailsClosedWhenFileRotatesWithUnreadBytes(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "error.log")
	statePath := filepath.Join(directory, "cursor.json")
	original := strings.Join([]string{
		"2026/11/23 08:00:00 [error] 123#123: first failure",
		"2026/11/23 08:00:01 [error] 123#123: second failure",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewDurableCollector(path, statePath, DefaultMaximumBytes, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, cursor, err := collector.CollectWithCursor(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.Commit(cursor); err != nil {
		t.Fatal(err)
	}

	rotated := filepath.Join(directory, "error.log.1")
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("2026/11/23 08:00:02 [error] 123#123: new file\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := collector.CollectWithCursor(time.Now().UTC()); err == nil {
		t.Fatal("expected rotation with unread bytes to fail closed")
	}
}

func TestDurableCollectorDoesNotAdvancePastInvalidOversizedEntry(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "error.log")
	statePath := filepath.Join(directory, "cursor.json")
	line := "2026/11/23 08:00:00 [error] 123#123: " + strings.Repeat("x", MaximumMessageBytes+1) + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewDurableCollector(path, statePath, DefaultMaximumBytes, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := collector.CollectWithCursor(time.Now().UTC()); err == nil {
		t.Fatal("expected oversized recognized log entry to fail closed")
	}
	if _, exists, err := collector.loadCursor(); err != nil {
		t.Fatal(err)
	} else if exists {
		t.Fatal("invalid log entry must not advance or create the durable cursor")
	}
}
