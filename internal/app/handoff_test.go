package app

import (
	"testing"

	"nadi-agent/internal/control"
)

func TestInactiveActivationStatePreservesSuspendedAndRevokedStates(t *testing.T) {
	cases := []struct {
		name        string
		application control.Application
		expected    string
	}{
		{
			name: "suspended",
			application: control.Application{
				RegistrationStatus: "approved",
				ActivationStatus:   "suspended",
			},
			expected: "suspended",
		},
		{
			name: "revoked",
			application: control.Application{
				RegistrationStatus: "approved",
				ActivationStatus:   "revoked",
			},
			expected: "revoked",
		},
		{
			name: "pending approval",
			application: control.Application{
				RegistrationStatus: "pending",
				ActivationStatus:   "pending",
			},
			expected: "pending_approval",
		},
		{
			name: "approved pending activation",
			application: control.Application{
				RegistrationStatus: "approved",
				ActivationStatus:   "pending",
			},
			expected: "pending_activation",
		},
		{
			name:        "unknown application",
			application: control.Application{},
			expected:    "unknown",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := inactiveActivationState(testCase.application, false)
			if actual != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, actual)
			}
		})
	}
}

func TestInactiveActivationStateCannotOverrideAnOpenGate(t *testing.T) {
	actual := inactiveActivationState(control.Application{
		RegistrationStatus: "pending",
		ActivationStatus:   "suspended",
	}, true)

	if actual != "active" {
		t.Fatalf("expected an open effective gate to map to active, got %q", actual)
	}
}
