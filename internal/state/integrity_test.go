package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRejectsModifiedPersistedState(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(State{AgentInstanceID: "agent-integrity-test"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, "state.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Replace(content, []byte("agent-integrity-test"), []byte("agent-tampered-test"), 1)
	if bytes.Equal(modified, content) {
		t.Fatal("test fixture did not contain the expected state value")
	}
	if err := os.WriteFile(path, modified, 0600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	if _, err := reopened.Load(); err == nil {
		t.Fatal("modified Agent state must fail Ed25519 integrity verification")
	}
}

func TestOpenRejectsMissingIntegrityKeyForExistingState(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "state.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(directory); err == nil {
		t.Fatal("existing state without its integrity key must fail closed")
	}
}

func TestLoadReadOnlyRejectsModifiedPersistedState(t *testing.T) {
	directory := t.TempDir()
	store, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(State{AgentInstanceID: "agent-integrity-test"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(directory, "state.json")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Replace(content, []byte("agent-integrity-test"), []byte("agent-tampered-test"), 1)
	if bytes.Equal(modified, content) {
		t.Fatal("test fixture did not contain the expected state value")
	}
	if err := os.WriteFile(path, modified, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadReadOnly(directory); err == nil {
		t.Fatal("read-only restore must reject a modified Agent state")
	}
}

func TestOpenRejectsSymlinkedIntegrityKey(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pem")
	if err := os.WriteFile(target, []byte("not a key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, integrityKeyFilename)); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(directory); err == nil {
		t.Fatal("symlinked state integrity key must be rejected")
	}
}
