package identity

import (
	"os"
	"path/filepath"
	"testing"

	"nadi-agent/internal/state"
)

func TestEnsureCreatesAndPersistsIdentity(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	first, err := Ensure(store)
	if err != nil {
		t.Fatalf("ensure identity: %v", err)
	}

	if first.AgentInstanceID == "" {
		t.Fatal("agent instance ID is empty")
	}

	if first.Hostname == "" {
		t.Fatal("hostname is empty")
	}

	if first.MachineFingerprint == "" {
		t.Fatal("machine fingerprint is empty")
	}

	if first.EnrollmentStatus != "unregistered" {
		t.Fatalf("unexpected enrollment status: %q", first.EnrollmentStatus)
	}

	second, err := Ensure(store)
	if err != nil {
		t.Fatalf("ensure identity on second call: %v", err)
	}

	if first.AgentInstanceID != second.AgentInstanceID {
		t.Fatal("agent instance ID changed between calls")
	}
}

func TestEnsureDoesNotRecreateIdentityWhenStateIsMissingFromExistingInstallation(t *testing.T) {
	directory := t.TempDir()
	store, err := state.Open(directory)
	if err != nil {
		t.Fatalf("open fresh state store: %v", err)
	}

	if _, err := Ensure(store); err != nil {
		t.Fatalf("initialize fresh Agent identity: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close fresh state store: %v", err)
	}

	statePath := filepath.Join(directory, "state.json")
	if err := os.Remove(statePath); err != nil {
		t.Fatalf("remove persisted state fixture: %v", err)
	}

	reopened, err := state.Open(directory)
	if err != nil {
		t.Fatalf("reopen existing installation: %v", err)
	}
	defer reopened.Close()

	if _, err := Ensure(reopened); err == nil {
		t.Fatal("missing state in an existing installation must require recovery")
	}

	if _, err := os.Lstat(statePath); !os.IsNotExist(err) {
		t.Fatalf("Ensure must not recreate the missing state file; lstat error = %v", err)
	}
}


func TestEnsureRejectsMissingStateAndIntegrityKeyWhenInstallMarkerRemains(t *testing.T) {
	directory := t.TempDir()
	store, err := state.Open(directory)
	if err != nil {
		t.Fatalf("open fresh state store: %v", err)
	}
	if _, err := Ensure(store); err != nil {
		t.Fatalf("initialize fresh Agent identity: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close fresh state store: %v", err)
	}

	for _, path := range []string{
		filepath.Join(directory, "state.json"),
		filepath.Join(directory, "state-integrity-private.pem"),
	} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove existing installation artifact %s: %v", filepath.Base(path), err)
		}
	}

	if _, err := state.Open(directory); err == nil {
		t.Fatal("existing installation marker must prevent identity and integrity key regeneration")
	}

	if _, err := os.Stat(filepath.Join(directory, "state-integrity-private.pem")); !os.IsNotExist(err) {
		t.Fatalf("Open must not regenerate the missing integrity key; stat error = %v", err)
	}
}
