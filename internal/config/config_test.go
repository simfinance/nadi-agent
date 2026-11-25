package config

import (
	"testing"
	"time"
)

func TestValidateRequiresHTTPSCentralURL(t *testing.T) {
	cfg := Config{
		CentralURL:   "http://central.example.test",
		LogLevel:     "info",
		PollInterval: 30 * time.Second,
		HTTPTimeout:  10 * time.Second,
		StateDir:     "/tmp/nadi-agent-test",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected HTTP Central URL to be rejected")
	}
}

func TestValidateAcceptsHTTPSCentralURL(t *testing.T) {
	cfg := Config{
		CentralURL:   "https://central.example.test",
		LogLevel:     "info",
		PollInterval: 30 * time.Second,
		HTTPTimeout:  10 * time.Second,
		StateDir:     "/tmp/nadi-agent-test",
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid configuration, got: %v", err)
	}
}

func TestLoadDisablesLogTelemetryByDefault(t *testing.T) {
	t.Setenv("NADI_AGENT_LOG_TELEMETRY_ENABLED", "")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	if cfg.LogTelemetryEnabled {
		t.Fatal("Agent log telemetry must be disabled by default")
	}
}

func TestLoadEnablesLogTelemetryOnlyWithExplicitOptIn(t *testing.T) {
	t.Setenv("NADI_AGENT_LOG_TELEMETRY_ENABLED", "true")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load opt-in config: %v", err)
	}
	if !cfg.LogTelemetryEnabled {
		t.Fatal("expected explicit Agent log telemetry opt-in to be honored")
	}
}

func TestLoadRejectsInvalidLogTelemetrySetting(t *testing.T) {
	t.Setenv("NADI_AGENT_LOG_TELEMETRY_ENABLED", "sometimes")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid log telemetry setting to be rejected")
	}
}

func TestSystemLogTelemetryIsDisabledByDefault(t *testing.T) {
	t.Setenv("NADI_AGENT_SYSTEM_LOG_TELEMETRY_ENABLED", "")
	t.Setenv("NADI_AGENT_NGINX_ERROR_LOG_PATH", "")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	if cfg.SystemLogTelemetryEnabled {
		t.Fatal("system log telemetry must be disabled by default")
	}
	if cfg.NginxErrorLogPath != "" {
		t.Fatalf("expected empty Nginx log path by default, got %q", cfg.NginxErrorLogPath)
	}
}

func TestSystemLogTelemetryRequiresExplicitPath(t *testing.T) {
	t.Setenv("NADI_AGENT_SYSTEM_LOG_TELEMETRY_ENABLED", "true")
	t.Setenv("NADI_AGENT_NGINX_ERROR_LOG_PATH", "")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")

	if _, err := Load(); err == nil {
		t.Fatal("expected system log telemetry without a configured path to be rejected")
	}
}

func TestSystemLogTelemetryAcceptsExplicitPath(t *testing.T) {
	t.Setenv("NADI_AGENT_SYSTEM_LOG_TELEMETRY_ENABLED", "true")
	t.Setenv("NADI_AGENT_NGINX_ERROR_LOG_PATH", "/var/log/nginx/error.log")
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load explicit system log config: %v", err)
	}
	if !cfg.SystemLogTelemetryEnabled || cfg.NginxErrorLogPath != "/var/log/nginx/error.log" {
		t.Fatalf("unexpected system log configuration: %#v", cfg)
	}
}

func TestValidateRejectsRelativeHandoffSocketPath(t *testing.T) {
	cfg := Config{
		CentralURL:        "https://central.example.test",
		LogLevel:          "info",
		PollInterval:      30 * time.Second,
		HTTPTimeout:       10 * time.Second,
		StateDir:          "/tmp/nadi-agent-test",
		HandoffSocketPath: "relative/handoff.sock",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected relative handoff socket path to be rejected")
	}
}


func TestLoadUsesCanonicalStateDirectory(t *testing.T) {
	t.Setenv("NADI_CENTRAL_URL", "https://central.example.test")
	t.Setenv("NADI_STATE_DIR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	if cfg.StateDir != "/var/lib/nadi/state" {
		t.Fatalf("expected canonical state directory, got %q", cfg.StateDir)
	}
}
