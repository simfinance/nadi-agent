package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorePersistsState(t *testing.T) {
	directory := t.TempDir()

	store, err := Open(directory)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	if _, err := store.Load(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	initial := State{
		AgentInstanceID:  "8f3d2f44-8b8d-4c91-8e35-58c5a6f79e14",
		Hostname:         "test-agent",
		EnrollmentStatus: "unregistered",
		CreatedAt:        time.Now().UTC(),
	}

	if err := store.Save(initial); err != nil {
		t.Fatalf("save state: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}

	if loaded.AgentInstanceID != initial.AgentInstanceID {
		t.Fatalf("agent instance ID changed: got %q", loaded.AgentInstanceID)
	}

	if loaded.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("unexpected schema version: got %d", loaded.SchemaVersion)
	}

	if loaded.UpdatedAt.IsZero() {
		t.Fatal("updated_at was not populated")
	}
}

func TestStoreUsesRestrictedPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")

	store, err := Open(directory)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	defer store.Close()

	current := State{
		AgentInstanceID: "8f3d2f44-8b8d-4c91-8e35-58c5a6f79e14",
	}

	if err := store.Save(current); err != nil {
		t.Fatalf("save state: %v", err)
	}

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}

	if directoryInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected directory permissions 0700, got %04o", directoryInfo.Mode().Perm())
	}

	stateInfo, err := os.Stat(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}

	if stateInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected state file permissions 0600, got %04o", stateInfo.Mode().Perm())
	}
}

func TestStorePreventsConcurrentAgentProcess(t *testing.T) {
	directory := t.TempDir()

	first, err := Open(directory)
	if err != nil {
		t.Fatalf("open first state store: %v", err)
	}
	defer first.Close()

	second, err := Open(directory)
	if err == nil {
		second.Close()
		t.Fatal("expected second state store to be rejected")
	}
}

func TestOpenRejectsLegacyPersistentDataBeforeCreatingCanonicalState(t *testing.T) {
	legacyArtifacts := []string{
		"state.json",
		"state-integrity-private.pem",
		"agent.lock",
		"log-dedupe",
		"nginx-error-log-cursor.json",
		"telemetry-delivery",
	}

	for _, artifact := range legacyArtifacts {
		t.Run(artifact, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "nadi")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}

			legacyPath := filepath.Join(root, artifact)
			if artifact == "log-dedupe" || artifact == "telemetry-delivery" {
				if err := os.Mkdir(legacyPath, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(legacyPath, []byte("legacy"), 0600); err != nil {
				t.Fatal(err)
			}

			canonicalStateDir := filepath.Join(root, "state")
			if _, err := Open(canonicalStateDir); err == nil {
				t.Fatal("expected legacy persistent data to block canonical state initialization")
			}

			if _, err := os.Lstat(canonicalStateDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canonical state directory must not be created after legacy data is detected: %v", err)
			}
		})
	}
}
