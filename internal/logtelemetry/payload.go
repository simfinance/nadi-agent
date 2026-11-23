package logtelemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaximumMessageBytes       = 8192
	MaximumContextStringRunes = 2048
	MaximumContextFields      = 50
	MaximumChannelBytes       = 100
)

var (
	allowedLevels = map[string]struct{}{
		"emergency": {},
		"alert":     {},
		"critical":  {},
		"error":     {},
		"warning":   {},
		"notice":    {},
		"info":      {},
		"debug":     {},
	}

	sensitiveAssignmentPattern = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|password|passwd|token|access[_-]?token|refresh[_-]?token|cookie|set-cookie|api[_-]?key|secret|credential|private[_-]?key)\b\s*[:=]\s*(?:bearer\s+)?("[^"]*"|'[^']*'|[^\s,;]+)`)
	cookieHeaderPattern        = regexp.MustCompile(`(?i)\b(cookie|set-cookie)\b\s*[:=]\s*[^,]+`)
	bearerTokenPattern         = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]+=*`)
	stackTracePattern          = regexp.MustCompile(`(?im)^\s*(?:at\s+[A-Za-z0-9_.$/<>-]+|goroutine\s+\d+\s+\[|#\d+\s+0x[0-9a-f]+)`)
)

type NginxErrorLog struct {
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Source    string `json:"source,omitempty"`
}

type ApplicationLog struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Channel   string         `json:"channel"`
	Message   string         `json:"message"`
	Context   map[string]any `json:"context,omitempty"`
}

func NormalizeNginxErrorLog(raw []byte) (json.RawMessage, error) {
	var input NginxErrorLog
	if err := decodeStrict(raw, &input); err != nil {
		return nil, fmt.Errorf("decode Nginx error log payload: %w", err)
	}

	timestamp, err := normalizeTimestamp(input.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid Nginx error log timestamp: %w", err)
	}

	severity := strings.ToLower(strings.TrimSpace(input.Severity))
	if _, allowed := allowedLevels[severity]; !allowed {
		return nil, fmt.Errorf("unsupported Nginx error log severity %q", input.Severity)
	}

	if input.Source != "" && input.Source != "nginx" {
		return nil, errors.New("Nginx error log source must be nginx when supplied")
	}

	message, err := normalizeMessage(input.Message)
	if err != nil {
		return nil, err
	}

	normalized, err := json.Marshal(NginxErrorLog{
		Timestamp: timestamp,
		Severity:  severity,
		Message:   message,
		Source:    "nginx",
	})
	if err != nil {
		return nil, fmt.Errorf("encode normalized Nginx error log payload: %w", err)
	}
	return normalized, nil
}

func NormalizeApplicationLog(raw []byte) (json.RawMessage, error) {
	var input struct {
		Timestamp string          `json:"timestamp"`
		Level     string          `json:"level"`
		Channel   string          `json:"channel"`
		Message   string          `json:"message"`
		Context   json.RawMessage `json:"context,omitempty"`
	}
	if err := decodeStrict(raw, &input); err != nil {
		return nil, fmt.Errorf("decode application log payload: %w", err)
	}

	timestamp, err := normalizeTimestamp(input.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid application log timestamp: %w", err)
	}

	level := strings.ToLower(strings.TrimSpace(input.Level))
	if _, allowed := allowedLevels[level]; !allowed {
		return nil, fmt.Errorf("unsupported application log level %q", input.Level)
	}

	channel := strings.TrimSpace(input.Channel)
	if channel == "" || len([]byte(channel)) > MaximumChannelBytes {
		return nil, fmt.Errorf("application log channel must contain 1 to %d bytes", MaximumChannelBytes)
	}

	message, err := normalizeMessage(input.Message)
	if err != nil {
		return nil, err
	}

	normalized := ApplicationLog{
		Timestamp: timestamp,
		Level:     level,
		Channel:   channel,
		Message:   message,
	}
	if len(input.Context) > 0 {
		contextFields, err := normalizeContext(input.Context)
		if err != nil {
			return nil, err
		}
		normalized.Context = contextFields
	}

	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode normalized application log payload: %w", err)
	}
	return encoded, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func normalizeTimestamp(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("timestamp is required")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", err
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}

func normalizeMessage(value string) (string, error) {
	message := strings.TrimSpace(value)
	if message == "" {
		return "", errors.New("log message is required")
	}
	if len([]byte(message)) > MaximumMessageBytes {
		return "", fmt.Errorf("log message exceeds %d bytes", MaximumMessageBytes)
	}
	if stackTracePattern.MatchString(message) {
		return "", errors.New("raw stack traces are not accepted in log telemetry")
	}

	message = cookieHeaderPattern.ReplaceAllString(message, "$1=[REDACTED]")
	message = sensitiveAssignmentPattern.ReplaceAllString(message, "$1=[REDACTED]")
	message = bearerTokenPattern.ReplaceAllString(message, "Bearer [REDACTED]")
	message = strings.Join(strings.Fields(message), " ")
	if message == "" || len([]byte(message)) > MaximumMessageBytes {
		return "", fmt.Errorf("normalized log message must contain 1 to %d bytes", MaximumMessageBytes)
	}
	return message, nil
}

func normalizeContext(raw json.RawMessage) (map[string]any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("application log context must be a JSON object")
	}
	if len(fields) > MaximumContextFields {
		return nil, fmt.Errorf("application log context exceeds %d top-level fields", MaximumContextFields)
	}

	normalized := make(map[string]any, len(fields))
	for key, rawValue := range fields {
		if isStackTraceKey(key) {
			return nil, errors.New("raw stack trace context fields are not accepted")
		}
		if isSensitiveContextKey(key) {
			normalized[key] = "[REDACTED]"
			continue
		}

		decoder := json.NewDecoder(bytes.NewReader(rawValue))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode application log context field %q: %w", key, err)
		}

		switch typed := value.(type) {
		case string:
			if utf8.RuneCountInString(typed) > MaximumContextStringRunes {
				return nil, fmt.Errorf("application log context field %q exceeds %d characters", key, MaximumContextStringRunes)
			}
			if stackTracePattern.MatchString(typed) {
				return nil, errors.New("raw stack traces are not accepted in log context")
			}
			normalized[key] = bearerTokenPattern.ReplaceAllString(
				sensitiveAssignmentPattern.ReplaceAllString(
					cookieHeaderPattern.ReplaceAllString(typed, "$1=[REDACTED]"),
					"$1=[REDACTED]",
				),
				"Bearer [REDACTED]",
			)
		case bool, json.Number, nil:
			normalized[key] = typed
		default:
			return nil, fmt.Errorf("application log context field %q has an unsupported value type", key)
		}
	}
	return normalized, nil
}

func isSensitiveContextKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	for _, fragment := range []string{
		"authorization",
		"password",
		"passwd",
		"token",
		"cookie",
		"api_key",
		"secret",
		"credential",
		"private_key",
	} {
		if strings.Contains(key, fragment) {
			return true
		}
	}
	return false
}

func isStackTraceKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	return key == "stack" || key == "stack_trace" || key == "stacktrace" || key == "trace"
}
