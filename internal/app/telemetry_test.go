package app

import (
	"testing"

	"nadi-agent/internal/activation"
)

func TestApplicationTelemetryAllowed(t *testing.T) {
	tests := []struct {
		name        string
		application string
		decisions   map[string]activation.GateDecision
		expected    bool
	}{
		{
			name:        "missing application decision",
			application: "app-1",
			decisions:   map[string]activation.GateDecision{},
			expected:    false,
		},
		{
			name:        "closed activation gate",
			application: "app-1",
			decisions: map[string]activation.GateDecision{
				"app-1": {
					Enabled:      false,
					Capabilities: []string{"application_metrics"},
				},
			},
			expected: false,
		},
		{
			name:        "server metrics does not authorize application telemetry",
			application: "app-1",
			decisions: map[string]activation.GateDecision{
				"app-1": {
					Enabled:      true,
					Capabilities: []string{"server_metrics"},
				},
			},
			expected: false,
		},
		{
			name:        "application metrics capability",
			application: "app-1",
			decisions: map[string]activation.GateDecision{
				"app-1": {
					Enabled:      true,
					Capabilities: []string{"application_metrics"},
				},
			},
			expected: true,
		},
		{
			name:        "database monitoring capability",
			application: "app-1",
			decisions: map[string]activation.GateDecision{
				"app-1": {
					Enabled:      true,
					Capabilities: []string{"database_monitoring"},
				},
			},
			expected: true,
		},
		{
			name:        "another application's capability cannot authorize this application",
			application: "app-1",
			decisions: map[string]activation.GateDecision{
				"app-2": {
					Enabled:      true,
					Capabilities: []string{"application_metrics"},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := applicationTelemetryAllowed(test.decisions, test.application)
			if actual != test.expected {
				t.Fatalf("applicationTelemetryAllowed() = %t, want %t", actual, test.expected)
			}
		})
	}
}

func TestApplicationStreamAllowedRequiresExactApplicationCapability(t *testing.T) {
	tests := []struct {
		name        string
		application string
		stream      string
		decisions   map[string]activation.GateDecision
		expected    bool
	}{
		{
			name:        "application metrics exact capability",
			application: "app-1",
			stream:      "application_metrics",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"application_metrics"}},
			},
			expected: true,
		},
		{
			name:        "database capability cannot authorize application metrics",
			application: "app-1",
			stream:      "application_metrics",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"database_monitoring"}},
			},
			expected: false,
		},
		{
			name:        "database exact capability",
			application: "app-1",
			stream:      "database_metrics",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"database_monitoring"}},
			},
			expected: true,
		},
		{
			name:        "another application grant cannot authorize this application",
			application: "app-1",
			stream:      "database_metrics",
			decisions: map[string]activation.GateDecision{
				"app-2": {Enabled: true, Capabilities: []string{"database_monitoring"}},
			},
			expected: false,
		},
		{
			name:        "server stream cannot use application authorization",
			application: "app-1",
			stream:      "server_metrics",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"server_metrics"}},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := applicationStreamAllowed(test.decisions, test.application, test.stream)
			if actual != test.expected {
				t.Fatalf("applicationStreamAllowed() = %t, want %t", actual, test.expected)
			}
		})
	}
}

func TestServerStreamAllowedRequiresExactServerCapability(t *testing.T) {
	tests := []struct {
		name      string
		stream    string
		decisions map[string]activation.GateDecision
		expected  bool
	}{
		{
			name:   "server metrics capability",
			stream: "server_metrics",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"server_metrics"}},
			},
			expected: true,
		},
		{
			name:   "server metrics cannot authorize system logs",
			stream: "nginx_error_logs",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"server_metrics"}},
			},
			expected: false,
		},
		{
			name:   "system logs exact capability",
			stream: "nginx_error_logs",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: true, Capabilities: []string{"system_logs"}},
			},
			expected: true,
		},
		{
			name:   "suspended application does not authorize server logs",
			stream: "nginx_error_logs",
			decisions: map[string]activation.GateDecision{
				"app-1": {Enabled: false, Capabilities: []string{"system_logs"}},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := serverStreamAllowed(test.decisions, test.stream)
			if actual != test.expected {
				t.Fatalf("serverStreamAllowed() = %t, want %t", actual, test.expected)
			}
		})
	}
}
