package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionJournalRecordsAndReloadsIntent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning-journal.json")

	store, journal, err := newProvisionJournal(path)
	if err != nil {
		t.Fatalf("create provisioning journal: %v", err)
	}
	if journal.Phase != "in_progress" || len(journal.TransactionID) != 32 {
		t.Fatalf("unexpected journal header: %#v", journal)
	}

	target := filepath.Join(directory, "new-file")
	index, err := store.AddIntent(&journal, "file", target)
	if err != nil {
		t.Fatalf("record file intent: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("reload provisioning journal: %v", err)
	}
	if len(loaded.Actions) != 1 || loaded.Actions[index].State != "intent" {
		t.Fatalf("unexpected reloaded journal: %#v", loaded)
	}
}

func TestProvisionJournalRollbackRemovesOnlyMatchingCreatedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-file")

	store, journal, err := newProvisionJournal(path)
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "file", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("created by this transaction"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}

	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("transaction-created file still exists: %v", err)
	}
	if journal.Phase != "rolled_back" {
		t.Fatalf("unexpected journal phase %q", journal.Phase)
	}
}

func TestProvisionJournalRollbackRefusesModifiedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-file")

	store, journal, err := newProvisionJournal(path)
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "file", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("modified externally"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := store.Rollback(&journal, []string{directory}); err == nil {
		t.Fatal("rollback must reject a resource whose fingerprint changed")
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("modified file must be preserved: %v", err)
	}
}

func TestProvisionJournalRollbackRefusesUnfingerprintedIntent(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-file")

	store, journal, err := newProvisionJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIntent(&journal, "file", target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("unknown transaction result"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := store.Rollback(&journal, []string{directory}); err == nil {
		t.Fatal("rollback must fail closed when an intent has no post-operation fingerprint")
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("unverified file must be preserved: %v", err)
	}
}

func TestProvisionJournalRollbackRemovesEmptyCreatedDirectory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-directory")

	store, journal, err := newProvisionJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	index, err := store.AddIntent(&journal, "directory", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}

	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback empty directory: %v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("transaction-created directory still exists: %v", err)
	}
}

func TestProvisionJournalRejectsSymlinkResource(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "linked-file")
	if err := os.Symlink(filepath.Join(directory, "missing"), target); err != nil {
		t.Fatal(err)
	}

	if _, err := fingerprintProvisionResource("file", target); err == nil {
		t.Fatal("symlink resources must not be fingerprinted")
	}
}

func TestProvisionJournalRollbackAllowlistAcceptsExactManagedRoot(t *testing.T) {
	root := "/opt/nadi"
	if !provisionJournalTargetAllowed(root, []string{root}) {
		t.Fatal("rollback allowlist must accept the exact managed root directory")
	}
	if provisionJournalTargetAllowed("/opt", []string{root}) {
		t.Fatal("rollback allowlist must reject a parent outside the managed root")
	}
}
