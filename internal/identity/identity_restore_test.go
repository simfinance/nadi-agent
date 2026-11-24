package identity

import (
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
