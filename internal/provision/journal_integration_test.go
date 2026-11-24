package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionJournalRetainsFixedServiceAccount(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "account", "nadi-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRetained(&journal, index); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(&journal); err != nil {
		t.Fatalf("commit with retained account: %v", err)
	}
	if journal.Actions[index].State != "retained" {
		t.Fatalf("expected service account to be retained, got %q", journal.Actions[index].State)
	}
}

func TestProvisionJournalParentRejectsGroupWritableDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatal(err)
	}

	_, _, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err == nil {
		t.Fatal("group-writable journal parent must be rejected")
	}
}

func TestProvisionJournalRollbackDoesNotDeleteRetainedAccount(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "account", "nadi-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRetained(&journal, index); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback with retained service account: %v", err)
	}
	if journal.Actions[index].State != "retained" {
		t.Fatalf("retained account state changed: %q", journal.Actions[index].State)
	}
}

func TestEnsureDirectoryTreeJournaledTracksAndRollsBackCreatedDirectory(t *testing.T) {
	root := t.TempDir()
	journalPath := filepath.Join(root, "journal.json")
	target := filepath.Join(root, "managed", "nested")

	store, journal, err := newProvisionJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := ensureDirectoryTreeJournaled(
		root,
		target,
		0700,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("create journaled directory tree: %v", err)
	}
	if len(journal.Actions) != 2 {
		t.Fatalf("expected both new directories to be journaled, got %d", len(journal.Actions))
	}

	if err := store.Rollback(&journal, []string{root}); err != nil {
		t.Fatalf("rollback journaled directory tree: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "managed")); !os.IsNotExist(err) {
		t.Fatalf("created parent directory remains after rollback: %v", err)
	}
}

func TestEnsureDirectoryTreeJournaledDoesNotChangeExistingMode(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "existing")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournal(filepath.Join(root, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	err = ensureDirectoryTreeJournaled(
		root,
		target,
		0700,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	)
	if err == nil {
		t.Fatal("existing directory with a different mode must be rejected")
	}

	metadata, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if metadata.Mode().Perm() != 0755 {
		t.Fatalf("existing directory mode was changed: %o", metadata.Mode().Perm())
	}
}

func TestInstallImmutableFileJournaledRollsBackCreatedFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "asset")
	store, journal, err := newProvisionJournal(filepath.Join(root, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := installImmutableFileJournaled(
		target,
		[]byte("trusted asset"),
		0600,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("install journaled file: %v", err)
	}
	if len(journal.Actions) != 1 || journal.Actions[0].State != "applied" {
		t.Fatalf("file creation was not recorded: %#v", journal.Actions)
	}

	if err := store.Rollback(&journal, []string{root}); err != nil {
		t.Fatalf("rollback journaled file: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("created file remains after rollback: %v", err)
	}
}


func TestProvisionLockRejectsConcurrentOperation(t *testing.T) {
    directory := t.TempDir()
    path := filepath.Join(directory, "provision.lock")

    unlock, err := acquireProvisionLockAt(path)
    if err != nil {
        t.Fatalf("acquire first provisioning lock: %v", err)
    }
    defer unlock()

    secondUnlock, err := acquireProvisionLockAt(path)
    if err == nil {
        secondUnlock()
        t.Fatal("second provisioning operation must not acquire an already-held lock")
    }
}
