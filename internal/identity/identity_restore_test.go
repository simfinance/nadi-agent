package identity

import (
	"os"
	"testing"
	"time"

	"nadi-agent/internal/state"
)

func TestVerifyReadOnlyPreservesExistingEnrollmentIdentity(t *testing.T) {
	directory := t.TempDir()
	store, err := state.Open(directory)
	if err != nil {
		t.Fatal(err)
	}

	fingerprint, err := machineFingerprint()
	if err != nil {
		t.Fatal(err)
	}

	expected := state.State{
		AgentInstanceID:    "agent-instance-restore",
		MachineFingerprint: fingerprint,
		CentralAgentID:     "central-agent",
		CentralServerID:    "central-server",
		EnrollmentStatus:   "registered",
		CreatedAt:          time.Now().UTC(),
		Applications: []state.EnrolledApplication{
			{
				ApplicationID:  "application-restore",
				ApplicationKey: "application-key-restore",
				RegistrationID: "registration-restore",
			},
		},
	}
	if err := store.Save(expected); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	actual, err := VerifyReadOnly(directory)
	if err != nil {
		t.Fatalf("existing identity verification failed: %v", err)
	}
	if actual.AgentInstanceID != expected.AgentInstanceID ||
		actual.CentralAgentID != expected.CentralAgentID ||
		actual.CentralServerID != expected.CentralServerID {
		t.Fatalf("existing Agent identity changed: %#v", actual)
	}
}

func TestVerifyReadOnlyRejectsDifferentMachineIdentity(t *testing.T) {
	directory := t.TempDir()
	store, err := state.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(state.State{
		AgentInstanceID:    "agent-instance-restore",
		MachineFingerprint: "different-machine",
		CentralAgentID:     "central-agent",
		CentralServerID:    "central-server",
		EnrollmentStatus:   "registered",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyReadOnly(directory); err != ErrMachineIdentityChanged {
		t.Fatalf("expected machine identity mismatch, got %v", err)
	}
}

func TestVerifyReadOnlyRejectsEmptyMachineFingerprint(t *testing.T) {
	directory := t.TempDir()
	store, err := state.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(state.State{
		AgentInstanceID:  "agent-instance-restore",
		CentralAgentID:   "central-agent",
		CentralServerID:  "central-server",
		EnrollmentStatus: "registered",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyReadOnly(directory); err != ErrMachineIdentityChanged {
		t.Fatalf("expected empty machine fingerprint to fail identity verification, got %v", err)
	}
}

func TestVerifyReadOnlyRejectsIncompleteOrDuplicateApplicationIdentity(t *testing.T) {
	fingerprint, err := machineFingerprint()
	if err != nil {
		t.Fatal(err)
	}

	baseApplication := state.EnrolledApplication{
		ApplicationID:  "application-one",
		RegistrationID: "registration-one",
	}
	secondApplication := state.EnrolledApplication{
		ApplicationID:  "application-two",
		RegistrationID: "registration-two",
	}

	tests := []struct {
		name         string
		applications []state.EnrolledApplication
	}{
		{
			name: "empty application ID",
			applications: []state.EnrolledApplication{
				{
					RegistrationID: "registration-one",
				},
			},
		},
		{
			name: "empty registration ID",
			applications: []state.EnrolledApplication{
				{
					ApplicationID: "application-one",
				},
			},
		},
		{
			name: "duplicate application ID",
			applications: []state.EnrolledApplication{
				baseApplication,
				{
					ApplicationID:  baseApplication.ApplicationID,
					RegistrationID: secondApplication.RegistrationID,
				},
			},
		},
		{
			name: "duplicate registration ID",
			applications: []state.EnrolledApplication{
				baseApplication,
				{
					ApplicationID:  secondApplication.ApplicationID,
					RegistrationID: baseApplication.RegistrationID,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			store, err := state.Open(directory)
			if err != nil {
				t.Fatal(err)
			}

			if err := store.Save(state.State{
				AgentInstanceID:    "agent-instance-restore",
				MachineFingerprint: fingerprint,
				CentralAgentID:     "central-agent",
				CentralServerID:    "central-server",
				EnrollmentStatus:   "registered",
				Applications:       test.applications,
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			if _, err := VerifyReadOnly(directory); err == nil {
				t.Fatal("expected invalid application identity inventory to be rejected")
			}
		})
	}
}

func TestValidMachineID(t *testing.T) {
	tests := []struct {
		name      string
		machineID string
		valid     bool
	}{
		{
			name:      "valid machine ID",
			machineID: "0123456789abcdef0123456789abcdef",
			valid:     true,
		},
		{
			name:      "uppercase hexadecimal machine ID",
			machineID: "0123456789ABCDEF0123456789ABCDEF",
			valid:     true,
		},
		{
			name:      "short machine ID",
			machineID: "0123456789abcdef",
			valid:     false,
		},
		{
			name:      "non-hexadecimal machine ID",
			machineID: "0123456789abcdef0123456789abcdefg",
			valid:     false,
		},
		{
			name:      "all-zero machine ID",
			machineID: "00000000000000000000000000000000",
			valid:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := validMachineID(test.machineID); actual != test.valid {
				t.Fatalf("validMachineID(%q) = %v, want %v", test.machineID, actual, test.valid)
			}
		})
	}
}

func TestReadMachineIDLimitsFileSize(t *testing.T) {
	directory := t.TempDir()
	path := directory + "/machine-id"

	if err := os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0600); err != nil {
		t.Fatal(err)
	}

	machineID, err := readMachineID(path)
	if err != nil {
		t.Fatalf("read valid machine ID: %v", err)
	}
	if machineID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected machine ID: %q", machineID)
	}

	if err := os.WriteFile(path, make([]byte, 1024*1024), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := readMachineID(path); err == nil {
		t.Fatal("expected oversized machine ID file to be rejected")
	}
}

func TestDecodeMachineIDCanonicalizesHexCase(t *testing.T) {
	lowercase, valid := decodeMachineID("0123456789abcdef0123456789abcdef")
	if !valid {
		t.Fatal("expected lowercase machine ID to be valid")
	}

	uppercase, valid := decodeMachineID("0123456789ABCDEF0123456789ABCDEF")
	if !valid {
		t.Fatal("expected uppercase machine ID to be valid")
	}

	if string(lowercase) != string(uppercase) {
		t.Fatal("equivalent hexadecimal machine IDs must decode to identical bytes")
	}
}
