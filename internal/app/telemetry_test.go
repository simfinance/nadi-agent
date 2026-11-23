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
