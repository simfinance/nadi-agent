package provision

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProvisionLockCoordinatesSeparateProcessesAndReusesStaleLockFile(t *testing.T) {
	const childMarker = "NADI_PROVISION_LOCK_CHILD"
	if os.Getenv(childMarker) == "1" {
		lockPath := os.Getenv("NADI_PROVISION_LOCK_PATH")
		unlock, err := acquireProvisionLockAt(lockPath)
		if err != nil {
			os.Exit(3)
		}
		unlock()
		os.Exit(0)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "provision.lock")
	unlock, err := acquireProvisionLockAt(path)
	if err != nil {
		t.Fatalf("acquire parent provisioning lock: %v", err)
	}

	runChild := func() error {
		command := exec.Command(
			os.Args[0],
			"-test.run=^TestProvisionLockCoordinatesSeparateProcessesAndReusesStaleLockFile$",
		)
		command.Env = append(
			os.Environ(),
			childMarker+"=1",
			"NADI_PROVISION_LOCK_PATH="+path,
		)
		return command.Run()
	}

	if err := runChild(); err == nil {
		unlock()
		t.Fatal("separate process acquired a lock while the parent process held it")
	}

	unlock()

	if err := runChild(); err != nil {
		t.Fatalf("separate process could not acquire the persistent lock file after release: %v", err)
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("persistent lock file should remain available for future flock operations: %v", err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		t.Fatal("persistent provisioning lock path must remain a regular non-symlink file")
	}
}

func TestProvisionLockIsReleasedAfterAbruptProcessExit(t *testing.T) {
	const childMarker = "NADI_PROVISION_LOCK_CRASH_CHILD"
	if os.Getenv(childMarker) == "1" {
		lockPath := os.Getenv("NADI_PROVISION_LOCK_PATH")
		if _, err := acquireProvisionLockAt(lockPath); err != nil {
			os.Exit(3)
		}

		os.Exit(0)
	}

	directory := t.TempDir()
	path := filepath.Join(directory, "provision.lock")
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestProvisionLockIsReleasedAfterAbruptProcessExit$",
	)
	command.Env = append(
		os.Environ(),
		childMarker+"=1",
		"NADI_PROVISION_LOCK_PATH="+path,
	)
	if err := command.Run(); err != nil {
		t.Fatalf("child process failed before abrupt exit: %v", err)
	}

	unlock, err := acquireProvisionLockAt(path)
	if err != nil {
		t.Fatalf("kernel-released lock could not be acquired after child process exit: %v", err)
	}
	unlock()
}

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
