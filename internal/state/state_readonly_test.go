package state

import (
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestLoadReadOnlyReturnsPersistedIdentity(t *testing.T) {
    directory := t.TempDir()
    store, err := Open(directory)
    if err != nil {
        t.Fatal(err)
    }

    expected := State{
        AgentInstanceID: "agent-instance-restore",
        MachineFingerprint: "machine-fingerprint",
        EnrollmentStatus: "registered",
        CentralAgentID: "central-agent",
        CentralServerID: "central-server",
        CreatedAt: time.Now().UTC(),
    }
    if err := store.Save(expected); err != nil {
        t.Fatal(err)
    }
    if err := store.Close(); err != nil {
        t.Fatal(err)
    }

    actual, err := LoadReadOnly(directory)
    if err != nil {
        t.Fatalf("read-only state load failed: %v", err)
    }
    if actual.AgentInstanceID != expected.AgentInstanceID ||
        actual.CentralAgentID != expected.CentralAgentID ||
        actual.CentralServerID != expected.CentralServerID ||
        actual.EnrollmentStatus != expected.EnrollmentStatus {
        t.Fatalf("unexpected restored identity: %#v", actual)
    }
}

func TestLoadReadOnlyRejectsSymlinkedStateFile(t *testing.T) {
    directory := t.TempDir()
    target := filepath.Join(directory, "target.json")
    if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
        t.Fatal(err)
    }
    if err := os.Symlink(target, filepath.Join(directory, "state.json")); err != nil {
        t.Fatal(err)
    }

    if _, err := LoadReadOnly(directory); err == nil {
        t.Fatal("symlinked state file must be rejected")
    }
}

func TestLoadReadOnlyRejectsInsecureStateFileMode(t *testing.T) {
    directory := t.TempDir()
    store, err := Open(directory)
    if err != nil {
        t.Fatal(err)
    }
    if err := store.Save(State{AgentInstanceID: "agent-instance"}); err != nil {
        t.Fatal(err)
    }
    if err := store.Close(); err != nil {
        t.Fatal(err)
    }

    if err := os.Chmod(filepath.Join(directory, "state.json"), 0644); err != nil {
        t.Fatal(err)
    }
    if _, err := LoadReadOnly(directory); err == nil {
        t.Fatal("world-readable state file must be rejected")
    }
}
