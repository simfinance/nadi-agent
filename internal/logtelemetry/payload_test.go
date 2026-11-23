package logtelemetry

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNormalizeNginxErrorLog(t *testing.T) {
	raw := []byte(`{
		"timestamp":"2026-11-23T08:00:00+07:00",
		"severity":"critical",
		"message":"connect failed Authorization: Bearer top-secret, Cookie: session=alpha; csrf=beta",
		"source":"nginx"
	}`)

	normalized, err := NormalizeNginxErrorLog(raw)
	if err != nil {
		t.Fatalf("normalize Nginx log: %v", err)
	}

	var result NginxErrorLog
	if err := json.Unmarshal(normalized, &result); err != nil {
		t.Fatalf("decode normalized Nginx log: %v", err)
	}
	if result.Timestamp != "2026-11-23T01:00:00Z" {
		t.Fatalf("timestamp was not normalized to UTC: %q", result.Timestamp)
	}
	if result.Severity != "critical" || result.Source != "nginx" {
		t.Fatalf("unexpected Nginx log metadata: %#v", result)
	}
	for _, secret := range []string{"top-secret", "session=alpha", "csrf=beta"} {
		if strings.Contains(result.Message, secret) {
			t.Fatalf("Nginx message retained sensitive value %q: %s", secret, result.Message)
		}
	}
}

func TestNormalizeNginxErrorLogRejectsUnknownFieldsAndInvalidSeverity(t *testing.T) {
	unknownField := []byte(`{
		"timestamp":"2026-11-23T08:00:00Z",
		"severity":"error",
		"message":"failure",
		"raw_stack":"not allowed"
	}`)
	if _, err := NormalizeNginxErrorLog(unknownField); err == nil {
		t.Fatal("expected unknown Nginx log field to be rejected")
	}

	invalidSeverity := []byte(`{
		"timestamp":"2026-11-23T08:00:00Z",
		"severity":"fatal",
		"message":"failure"
	}`)
	if _, err := NormalizeNginxErrorLog(invalidSeverity); err == nil {
		t.Fatal("expected unsupported Nginx severity to be rejected")
	}
}

func TestNormalizeApplicationLogRedactsSensitiveContext(t *testing.T) {
	raw := []byte(`{
		"timestamp":"2026-11-23T08:00:00Z",
		"level":"warning",
		"channel":"auth",
		"message":"login failed password=hunter2 Authorization: Bearer abc123",
		"context":{
			"user_id":42,
			"password":"hunter2",
			"cookie":"session=secret",
			"attempt":true
		}
	}`)

	normalized, err := NormalizeApplicationLog(raw)
	if err != nil {
		t.Fatalf("normalize application log: %v", err)
	}

	var result ApplicationLog
	if err := json.Unmarshal(normalized, &result); err != nil {
		t.Fatalf("decode normalized application log: %v", err)
	}
	if result.Level != "warning" || result.Channel != "auth" {
		t.Fatalf("unexpected application log metadata: %#v", result)
	}
	if strings.Contains(result.Message, "hunter2") || strings.Contains(result.Message, "abc123") {
		t.Fatalf("application log message retained sensitive data: %s", result.Message)
	}
	if result.Context["password"] != "[REDACTED]" || result.Context["cookie"] != "[REDACTED]" {
		t.Fatalf("sensitive context fields were not redacted: %#v", result.Context)
	}
	if result.Context["user_id"] != json.Number("42") && result.Context["user_id"] != float64(42) {
		t.Fatalf("numeric context value was not preserved: %#v", result.Context["user_id"])
	}
}

func TestNormalizeApplicationLogRejectsUnknownFieldsAndInvalidContext(t *testing.T) {
	base := `"timestamp":"2026-11-23T08:00:00Z","level":"info","channel":"app","message":"ready"`

	tests := map[string]string{
		"unknown top-level field": `{` + base + `,"stack_trace":"raw"}`,
		"null context":            `{` + base + `,"context":null}`,
		"array context":           `{` + base + `,"context":[]}`,
		"nested context":          `{` + base + `,"context":{"nested":{"value":1}}}`,
		"stack trace key":         `{` + base + `,"context":{"stack_trace":"secret"}}`,
		"stack trace value":       `{` + base + `,"context":{"detail":" at App.Service.Runner"}}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NormalizeApplicationLog([]byte(raw)); err == nil {
				t.Fatal("expected invalid application log payload to be rejected")
			}
		})
	}
}

func TestNormalizeApplicationLogEnforcesLimits(t *testing.T) {
	base := `{"timestamp":"2026-11-23T08:00:00Z","level":"info","channel":"app","message":"ok","context":`
	tooManyFields := make(map[string]any)
	for index := 0; index <= MaximumContextFields; index++ {
		tooManyFields[fmt.Sprintf("field_%d", index)] = "value"
	}
	encodedContext, err := json.Marshal(tooManyFields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeApplicationLog([]byte(base + string(encodedContext) + "}")); err == nil {
		t.Fatal("expected context with more than 50 fields to be rejected")
	}

	longContext := map[string]string{"detail": strings.Repeat("x", MaximumContextStringRunes+1)}
	encodedContext, err = json.Marshal(longContext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeApplicationLog([]byte(base + string(encodedContext) + "}")); err == nil {
		t.Fatal("expected oversized context string to be rejected")
	}

	longMessage := strings.Repeat("x", MaximumMessageBytes+1)
	raw, err := json.Marshal(ApplicationLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "info",
		Channel:   "app",
		Message:   longMessage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeApplicationLog(raw); err == nil {
		t.Fatal("expected oversized message to be rejected")
	}
}

func TestNormalizeApplicationLogRejectsChannelOverOneHundredBytes(t *testing.T) {
	raw, err := json.Marshal(ApplicationLog{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "info",
		Channel:   strings.Repeat("c", MaximumChannelBytes+1),
		Message:   "message",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeApplicationLog(raw); err == nil {
		t.Fatal("expected oversized channel to be rejected")
	}
}

func TestNormalizeApplicationLogRejectsPHPAndPythonStackTraces(t *testing.T) {
	messages := []string{
		"Runtime failure\n#0 /var/www/app/Handler.php(42): App\\Service->run()\n#1 {main}",
		"Traceback (most recent call last):\n  File \"/srv/app.py\", line 42, in run",
	}

	for index, message := range messages {
		raw, err := json.Marshal(ApplicationLog{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Level:     "error",
			Channel:   "application",
			Message:   message,
		})
		if err != nil {
			t.Fatalf("encode stack trace case %d: %v", index, err)
		}

		if _, err := NormalizeApplicationLog(raw); err == nil {
			t.Fatalf("expected stack trace case %d to be rejected", index)
		}
	}
}

func TestNormalizeApplicationLogRedactsSpacedAndCamelCaseAPIKeys(t *testing.T) {
	raw := []byte(`{
		"timestamp":"2026-11-23T08:00:00Z",
		"level":"warning",
		"channel":"auth",
		"message":"request rejected api key=message-secret",
		"context":{
			"apiKey":"context-secret"
		}
	}`)

	normalized, err := NormalizeApplicationLog(raw)
	if err != nil {
		t.Fatalf("normalize application log: %v", err)
	}

	var result ApplicationLog
	if err := json.Unmarshal(normalized, &result); err != nil {
		t.Fatalf("decode normalized application log: %v", err)
	}

	if strings.Contains(result.Message, "message-secret") {
		t.Fatal("message retained a spaced API key value")
	}
	if result.Context["apiKey"] != "[REDACTED]" {
		t.Fatalf("camelCase API key context was not redacted: %#v", result.Context)
	}
}


func TestNormalizeApplicationLogAcceptsNullContextScalar(t *testing.T) {
	raw := []byte(`{
		"timestamp":"2026-11-23T08:00:00Z",
		"level":"info",
		"channel":"app",
		"message":"ready",
		"context":{"optional":null}
	}`)

	normalized, err := NormalizeApplicationLog(raw)
	if err != nil {
		t.Fatalf("normalize null context scalar: %v", err)
	}

	var result ApplicationLog
	if err := json.Unmarshal(normalized, &result); err != nil {
		t.Fatalf("decode normalized application log: %v", err)
	}
	if value, exists := result.Context["optional"]; !exists || value != nil {
		t.Fatalf("expected null scalar to be preserved, got %#v", result.Context)
	}
}
