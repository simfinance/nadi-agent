package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJournaledImmutableFilePreservesMatchingExistingFile(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.json")
	target := filepath.Join(directory, "existing-file")
	content := []byte("existing immutable content")

	if err := os.WriteFile(target, content, 0600); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := installImmutableFileJournaled(
		target,
		content,
		0600,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("matching existing immutable file should be accepted: %v", err)
	}

	if len(journal.Actions) != 0 {
		t.Fatalf("existing file must not be recorded as transaction-created: %#v", journal.Actions)
	}

	actual, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(content) {
		t.Fatalf("existing file changed: %q", actual)
	}
}

func TestJournaledImmutableFileRejectsDifferentExistingContent(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "journal.json")
	target := filepath.Join(directory, "existing-file")
	original := []byte("existing immutable content")

	if err := os.WriteFile(target, original, 0600); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}

	err = installImmutableFileJournaled(
		target,
		[]byte("replacement content"),
		0600,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	)
	if err == nil {
		t.Fatal("existing immutable file with different content must be rejected")
	}

	if len(journal.Actions) != 0 {
		t.Fatalf("rejected existing file must not be journaled as transaction-created: %#v", journal.Actions)
	}

	actual, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(original) {
		t.Fatalf("existing file was modified: %q", actual)
	}
}

func TestProvisionJournalRecoversAppliedFileAfterReload(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-file")

	store, journal, err := newProvisionJournalForOperation(journalPath, "restore_agent")
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "file", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("created by interrupted RESTORE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}

	reloadedStore, reloadedJournal, err := openProvisionJournal(journalPath)
	if err != nil {
		t.Fatalf("reload interrupted RESTORE journal: %v", err)
	}
	if err := reloadedStore.Rollback(&reloadedJournal, []string{directory}); err != nil {
		t.Fatalf("rollback reloaded RESTORE journal: %v", err)
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("fingerprint-matching transaction file remains after recovery: %v", err)
	}
	if reloadedJournal.Phase != "rolled_back" {
		t.Fatalf("unexpected recovered journal phase %q", reloadedJournal.Phase)
	}
}

func TestProvisionJournalRecoveryIsIdempotentAfterResourceRemoval(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "created-file")

	store, journal, err := newProvisionJournalForOperation(journalPath, "restore_agent")
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "file", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("created by interrupted RESTORE"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(target); err != nil {
		t.Fatalf("simulate crash after resource removal: %v", err)
	}

	reloadedStore, reloadedJournal, err := openProvisionJournal(journalPath)
	if err != nil {
		t.Fatalf("reload interrupted RESTORE journal: %v", err)
	}
	if err := reloadedStore.Rollback(&reloadedJournal, []string{directory}); err != nil {
		t.Fatalf("recovery must accept an already-removed transaction resource: %v", err)
	}

	if reloadedJournal.Phase != "rolled_back" ||
		reloadedJournal.Actions[index].State != "rolled_back" {
		t.Fatalf("recovery did not persist the idempotent rollback result: %#v", reloadedJournal)
	}
}

func TestProvisionJournalRecoveryPreservesUnfingerprintedIntent(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "provisioning-journal.json")
	target := filepath.Join(directory, "ambiguous-file")

	store, journal, err := newProvisionJournalForOperation(journalPath, "restore_agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddIntent(&journal, "file", target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("result of interrupted mutation"), 0600); err != nil {
		t.Fatal(err)
	}

	reloadedStore, reloadedJournal, err := openProvisionJournal(journalPath)
	if err != nil {
		t.Fatalf("reload interrupted RESTORE journal: %v", err)
	}
	if err := reloadedStore.Rollback(&reloadedJournal, []string{directory}); err == nil {
		t.Fatal("recovery must fail closed for an intent without a persisted fingerprint")
	}

	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("ambiguous transaction resource must be preserved: %v", err)
	}
	if reloadedJournal.Phase != "rollback_required" {
		t.Fatalf("ambiguous recovery must retain rollback_required phase, got %q", reloadedJournal.Phase)
	}
}

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

func TestIdentityRestoreJournalRollsBackOnlyNewMetadataAndPreservesAgentState(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "provisioning-journal.json")
	statePath := filepath.Join(directory, "state.json")
	metadataPath := filepath.Join(directory, "provisioning-complete.json")

	if err := os.WriteFile(statePath, []byte("existing Agent identity"), 0600); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournalForOperation(journalPath, "restore_agent")
	if err != nil {
		t.Fatalf("create identity restore journal: %v", err)
	}
	if journal.Operation != "restore_agent" {
		t.Fatalf("unexpected journal operation %q", journal.Operation)
	}

	index, err := store.AddIntent(&journal, "file", metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, []byte("new non-secret completion metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkApplied(&journal, index); err != nil {
		t.Fatal(err)
	}

	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback identity restore metadata: %v", err)
	}

	if _, err := os.Lstat(metadataPath); !os.IsNotExist(err) {
		t.Fatalf("new completion metadata was not rolled back: %v", err)
	}
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("existing Agent state was removed: %v", err)
	}
	if string(state) != "existing Agent identity" {
		t.Fatalf("existing Agent state was modified: %q", state)
	}
}

func TestProvisionJournalRejectsUnknownOperation(t *testing.T) {
	_, _, err := newProvisionJournalForOperation(filepath.Join(t.TempDir(), "journal.json"), "enroll_agent")
	if err == nil {
		t.Fatal("journal must reject operations outside the internal install/restore transaction allowlist")
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

func TestProvisionJournalRejectsRollbackAfterCommit(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(&journal); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(&journal, []string{directory}); err == nil {
		t.Fatal("committed provisioning journal must not be rolled back")
	}
}

func TestProvisionJournalRejectsCommitAfterRollback(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(&journal); err == nil {
		t.Fatal("rolled-back provisioning journal must not be committed")
	}
}

func TestProvisionJournalRejectsSymlinkedResourceParent(t *testing.T) {
	directory := t.TempDir()
	targetDirectory := filepath.Join(directory, "target")
	if err := os.Mkdir(targetDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(targetDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(linkedDirectory, "resource")
	if _, err := fingerprintProvisionResource("file", path); err == nil {
		t.Fatal("resource with a symlinked parent directory must be rejected")
	}
}
