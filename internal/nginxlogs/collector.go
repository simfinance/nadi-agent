package nginxlogs

import (
	"crypto/sha256"
	"encoding/hex"
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
	DefaultMaximumEntries       = 100
	MaximumAllowedBytes   int64 = 4 * 1024 * 1024
	MaximumAllowedEntries       = 500
)

var (
	linePattern   = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(emerg|alert|crit|error|warn|notice|info|debug)\] \d+#\d+: (.*)$`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Pattern   = regexp.MustCompile(`(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,}\b|::[0-9a-f]{1,4}(?::[0-9a-f]{0,4})*`)
	quotedPattern = regexp.MustCompile(`"[^"]*"`)
	secretPattern = regexp.MustCompile(`(?i)(token|password|passwd|secret|authorization|api[_-]?key)=([^\s,;]+)`)
)

type Status string

const (
	StatusAvailable   Status = "available"
	StatusDisabled    Status = "disabled"
	StatusUnavailable Status = "unavailable"
)

type Entry struct {
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level"`
	Fingerprint string    `json:"fingerprint"`
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

	level := matches[2]
	switch level {
	case "emerg", "alert", "crit", "error":
	default:
		return Entry{}, false
	}

	timestamp, err := time.ParseInLocation("2006/01/02 15:04:05", matches[1], time.Local)
	if err != nil {
		return Entry{}, false
	}

	normalized := strings.ToLower(matches[3])
	normalized = quotedPattern.ReplaceAllString(normalized, "<quoted>")
	normalized = secretPattern.ReplaceAllString(normalized, "$1=<redacted>")
	normalized = ipv4Pattern.ReplaceAllString(normalized, "<ip>")
	normalized = ipv6Pattern.ReplaceAllStringFunc(normalized, func(candidate string) string {
		if net.ParseIP(candidate) != nil {
			return "<address>"
		}

		return candidate
	})
	normalized = strings.Join(strings.Fields(normalized), " ")
	digest := sha256.Sum256([]byte(level + "|" + normalized))

	return Entry{
		Timestamp:   timestamp.UTC(),
		Level:       level,
		Fingerprint: hex.EncodeToString(digest[:]),
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
