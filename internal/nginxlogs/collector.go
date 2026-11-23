package nginxlogs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	DefaultMaximumBytes   int64 = 1024 * 1024
	DefaultMaximumEntries       = 20
	MaximumAllowedBytes   int64 = 4 * 1024 * 1024
	MaximumAllowedEntries       = 500
	MaximumMessageBytes         = 8192
)

var (
	linePattern   = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(emerg|alert|crit|error|warn|notice|info|debug)\] \d+#\d+: (.*)$`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Pattern   = regexp.MustCompile(`(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}\b|::[0-9a-f]{1,4}(?::[0-9a-f]{0,4})*`)
	quotedPattern = regexp.MustCompile(`"[^"]*"`)
	secretPattern = regexp.MustCompile(`(?i)(authorization|proxy-authorization|password|passwd|token|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|api[_-]?key|private[_-]?key|credential)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+`)
	cookiePattern = regexp.MustCompile(`(?i)(cookie|set-cookie)\s*[:=]\s*[^,]+`)
	bearerPattern = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`)
)

type Status string

const (
	StatusAvailable   Status = "available"
	StatusDisabled    Status = "disabled"
	StatusUnavailable Status = "unavailable"
)

type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	Message   string    `json:"message"`
	Source    string    `json:"source,omitempty"`
}

type Snapshot struct {
	Status      Status    `json:"status"`
	CollectedAt time.Time `json:"collected_at"`
	Entries     []Entry   `json:"entries"`
	ErrorCode   string    `json:"error_code,omitempty"`
}

type Collector struct {
	path       string
	maxBytes   int64
	maxEntries int
	statePath  string
}

type Cursor struct {
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	Offset       int64  `json:"offset"`
	ObservedSize int64  `json:"observed_size"`
}

func NewCollector(path string, maxBytes int64, maxEntries int) (*Collector, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &Collector{}, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Nginx error log path must be a clean absolute path")
	}
	if maxBytes <= 0 || maxBytes > MaximumAllowedBytes {
		return nil, fmt.Errorf("Nginx error log maximum bytes must be between 1 and %d", MaximumAllowedBytes)
	}
	if maxEntries <= 0 || maxEntries > MaximumAllowedEntries {
		return nil, fmt.Errorf("Nginx error log maximum entries must be between 1 and %d", MaximumAllowedEntries)
	}

	return &Collector{
		path:       path,
		maxBytes:   maxBytes,
		maxEntries: maxEntries,
	}, nil
}

func NewDurableCollector(path string, statePath string, maxBytes int64, maxEntries int) (*Collector, error) {
	collector, err := NewCollector(path, maxBytes, maxEntries)
	if err != nil {
		return nil, err
	}
	if collector.path == "" {
		return collector, nil
	}
	if !filepath.IsAbs(statePath) || filepath.Clean(statePath) != statePath {
		return nil, errors.New("Nginx error log cursor path must be a clean absolute path")
	}
	collector.statePath = statePath
	return collector, nil
}

func (c *Collector) CollectWithCursor(now time.Time) (Snapshot, Cursor, error) {
	snapshot := Snapshot{
		Status:      StatusDisabled,
		CollectedAt: now.UTC(),
		Entries:     make([]Entry, 0),
	}
	if c == nil || c.path == "" {
		return snapshot, Cursor{}, nil
	}
	if c.statePath == "" {
		return Snapshot{}, Cursor{}, errors.New("durable Nginx error log collector requires a cursor path")
	}

	file, err := openRegularFileNoFollow(c.path)
	if err != nil {
		snapshot.Status = StatusUnavailable
		snapshot.ErrorCode = classifyFileError(err)
		return snapshot, Cursor{}, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Snapshot{}, Cursor{}, fmt.Errorf("stat Nginx error log: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Snapshot{}, Cursor{}, errors.New("Nginx error log must be a regular non-symlink file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Snapshot{}, Cursor{}, errors.New("Nginx error log identity is unavailable")
	}

	current := Cursor{
		Device:       uint64(stat.Dev),
		Inode:        stat.Ino,
		ObservedSize: info.Size(),
	}
	previous, exists, err := c.loadCursor()
	if err != nil {
		return Snapshot{}, Cursor{}, err
	}
	if exists {
		if previous.Device != current.Device || previous.Inode != current.Inode {
			if previous.Offset < previous.ObservedSize {
				return Snapshot{}, Cursor{}, errors.New("Nginx error log rotated before the previous file was fully collected")
			}
		} else {
			if info.Size() < previous.Offset {
				return Snapshot{}, Cursor{}, errors.New("Nginx error log was truncated before the previous cursor was drained")
			}
			current.Offset = previous.Offset
		}
	}

	if current.Offset > info.Size() {
		return Snapshot{}, Cursor{}, errors.New("Nginx error log cursor exceeds current file size")
	}
	remaining := info.Size() - current.Offset
	readSize := remaining
	if readSize > c.maxBytes {
		readSize = c.maxBytes
	}
	if readSize == 0 {
		snapshot.Status = StatusAvailable
		return snapshot, current, nil
	}

	content := make([]byte, readSize)
	readCount, readErr := file.ReadAt(content, current.Offset)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return Snapshot{}, Cursor{}, fmt.Errorf("read Nginx error log at cursor: %w", readErr)
	}
	content = content[:readCount]

	consumed := 0
	for consumed < len(content) {
		newline := bytes.IndexByte(content[consumed:], '\n')
		lineEnd := -1
		lineLength := 0
		if newline >= 0 {
			lineEnd = consumed + newline
			lineLength = newline + 1
		} else if current.Offset+int64(len(content)) == info.Size() {
			lineEnd = len(content)
			lineLength = len(content) - consumed
		} else {
			break
		}

		line := string(content[consumed:lineEnd])
		if linePattern.MatchString(strings.TrimSpace(line)) {
			entry, valid := parseLine(line)
			if !valid {
				return Snapshot{}, Cursor{}, errors.New("Nginx error log entry failed schema validation; cursor was not advanced")
			}
			snapshot.Entries = append(snapshot.Entries, entry)
		}
		consumed += lineLength
		if len(snapshot.Entries) >= c.maxEntries {
			break
		}
	}
	if consumed == 0 && len(content) == c.maxBytes && current.Offset+int64(len(content)) < info.Size() {
		return Snapshot{}, Cursor{}, errors.New("Nginx error log contains a line larger than the configured read window")
	}

	current.Offset += int64(consumed)
	snapshot.Status = StatusAvailable
	return snapshot, current, nil
}

func (c *Collector) Commit(cursor Cursor) error {
	if c == nil || c.statePath == "" {
		return errors.New("durable Nginx error log cursor is not configured")
	}
	if cursor.Offset < 0 || cursor.ObservedSize < cursor.Offset {
		return errors.New("Nginx error log cursor is invalid")
	}

	content, err := json.Marshal(cursor)
	if err != nil {
		return fmt.Errorf("encode Nginx error log cursor: %w", err)
	}
	content = append(content, '\n')

	if err := os.MkdirAll(filepath.Dir(c.statePath), 0700); err != nil {
		return fmt.Errorf("create Nginx error log cursor directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(c.statePath), ".nginx-cursor-*.tmp")
	if err != nil {
		return fmt.Errorf("create Nginx error log cursor state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure Nginx error log cursor state: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write Nginx error log cursor state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync Nginx error log cursor state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Nginx error log cursor state: %w", err)
	}
	if err := os.Rename(temporaryPath, c.statePath); err != nil {
		return fmt.Errorf("replace Nginx error log cursor state: %w", err)
	}

	directory, err := os.Open(filepath.Dir(c.statePath))
	if err != nil {
		return fmt.Errorf("open Nginx error log cursor directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Nginx error log cursor directory: %w", err)
	}

	return nil
}

func (c *Collector) loadCursor() (Cursor, bool, error) {
	content, err := os.ReadFile(c.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return Cursor{}, false, nil
	}
	if err != nil {
		return Cursor{}, false, fmt.Errorf("read Nginx error log cursor: %w", err)
	}
	var cursor Cursor
	if err := json.Unmarshal(content, &cursor); err != nil {
		return Cursor{}, false, fmt.Errorf("decode Nginx error log cursor: %w", err)
	}
	if cursor.Offset < 0 || cursor.ObservedSize < cursor.Offset {
		return Cursor{}, false, errors.New("persisted Nginx error log cursor is invalid")
	}
	return cursor, true, nil
}

func (c *Collector) Collect(now time.Time) Snapshot {
	snapshot := Snapshot{
		Status:      StatusDisabled,
		CollectedAt: now.UTC(),
		Entries:     make([]Entry, 0),
	}
	if c == nil || c.path == "" {
		return snapshot
	}

	content, err := c.readBoundedFile()
	if err != nil {
		snapshot.Status = StatusUnavailable
		snapshot.ErrorCode = classifyFileError(err)
		return snapshot
	}

	snapshot.Status = StatusAvailable
	for _, line := range strings.Split(string(content), "\n") {
		entry, ok := parseLine(line)
		if !ok {
			continue
		}
		snapshot.Entries = append(snapshot.Entries, entry)
		if len(snapshot.Entries) >= c.maxEntries {
			break
		}
	}

	return snapshot
}

func (c *Collector) readBoundedFile() ([]byte, error) {
	file, err := openRegularFileNoFollow(c.path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("Nginx error log must be a regular non-symlink file")
	}

	size := info.Size()
	if size < 0 {
		return nil, errors.New("Nginx error log has an invalid size")
	}
	start := int64(0)
	if size > c.maxBytes {
		start = size - c.maxBytes
	}

	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	content := make([]byte, size-start)
	readCount, readErr := io.ReadFull(file, content)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, readErr
	}
	content = content[:readCount]

	if start > 0 {
		if newline := strings.IndexByte(string(content), '\n'); newline >= 0 {
			content = content[newline+1:]
		} else {
			content = content[:0]
		}
	}

	return content, nil
}

func openRegularFileNoFollow(path string) (*os.File, error) {
	directoryFD, err := syscall.Open(
		string(os.PathSeparator),
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}

	components := strings.Split(
		strings.TrimPrefix(path, string(os.PathSeparator)),
		string(os.PathSeparator),
	)

	for index, component := range components {
		flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
		if index < len(components)-1 {
			flags |= syscall.O_DIRECTORY
		}

		nextFD, openErr := syscall.Openat(directoryFD, component, flags, 0)
		_ = syscall.Close(directoryFD)
		if openErr != nil {
			return nil, openErr
		}

		directoryFD = nextFD
	}

	file := os.NewFile(uintptr(directoryFD), path)
	if file == nil {
		_ = syscall.Close(directoryFD)
		return nil, errors.New("could not create file handle for Nginx error log")
	}

	return file, nil
}

func parseLine(line string) (Entry, bool) {
	matches := linePattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 4 {
		return Entry{}, false
	}

	severity := matches[2]
	switch severity {
	case "emerg", "alert", "crit", "error", "warn", "notice", "info", "debug":
	default:
		return Entry{}, false
	}

	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", matches[1], time.Local)
	if err != nil {
		return Entry{}, false
	}

	message := strings.TrimSpace(matches[3])
	message = quotedPattern.ReplaceAllString(message, "<redacted>")
	message = secretPattern.ReplaceAllString(message, "$1=<redacted>")
	message = cookiePattern.ReplaceAllString(message, "$1=<redacted>")
	message = bearerPattern.ReplaceAllString(message, "Bearer <redacted>")
	message = ipv4Pattern.ReplaceAllString(message, "<ip>")
	message = ipv6Pattern.ReplaceAllStringFunc(message, func(candidate string) string {
		if net.ParseIP(candidate) != nil {
			return "<ip>"
		}
		return candidate
	})
	message = strings.Join(strings.Fields(message), " ")
	if message == "" || len([]byte(message)) > MaximumMessageBytes {
		return Entry{}, false
	}

	switch severity {
	case "emerg":
		severity = "emergency"
	case "crit":
		severity = "critical"
	case "warn":
		severity = "warning"
	}

	return Entry{
		Timestamp: timestamp.UTC(),
		Severity:  severity,
		Message:   message,
		Source:    "nginx",
	}, true
}

func classifyFileError(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "permission_denied"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "file_not_found"
	}
	return "file_unavailable"
}
