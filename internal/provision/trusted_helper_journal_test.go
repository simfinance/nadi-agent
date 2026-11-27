package provision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallProvisionAssetsJournaledRollsBackEarlierAssetsOnFailure(t *testing.T) {
	directory := t.TempDir()
	journalPath := filepath.Join(directory, "provisioning-journal.json")
	agentPath := filepath.Join(directory, "nadi-agent")
	helperPath := filepath.Join(directory, "nadi-provision")

	existingHelper := []byte("unexpected pre-existing helper")
	if err := os.WriteFile(helperPath, existingHelper, 0600); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournal(journalPath)
	if err != nil {
		t.Fatalf("create provisioning journal: %v", err)
	}

	assets := []provisionAsset{
		{
			path:    agentPath,
			content: []byte("verified signed Agent artifact"),
			mode:    0755,
			uid:     os.Geteuid(),
			gid:     os.Getegid(),
		},
		{
			path:    helperPath,
			content: []byte("verified signed Agent artifact"),
			mode:    0755,
			uid:     os.Geteuid(),
			gid:     os.Getegid(),
		},
	}

	if err := installProvisionAssetsJournaled(assets, store, &journal); err == nil {
		t.Fatal("installation must fail when a conflicting helper already exists")
	}

	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback partially installed assets: %v", err)
	}

	if _, err := os.Lstat(agentPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("earlier Agent asset must be removed by rollback, got: %v", err)
	}

	actualHelper, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatalf("read pre-existing helper after rollback: %v", err)
	}
	if string(actualHelper) != string(existingHelper) {
		t.Fatal("rollback must preserve the conflicting pre-existing helper byte-for-byte")
	}

	if journal.Phase != "rolled_back" {
		t.Fatalf("expected rolled_back journal phase, got %q", journal.Phase)
	}
	if len(journal.Actions) != 1 || journal.Actions[0].State != "rolled_back" {
		t.Fatalf("expected only the created Agent asset to be rolled back, got %#v", journal.Actions)
	}
}

func TestInstallAgentAssetsJournaledRestoresMissingHelperFromVerifiedArtifact(t *testing.T) {
	root := t.TempDir()
	prepareAgentAssetDirectories(t, root)

	artifact := []byte("verified signed Agent release artifact")
	artifactPath := filepath.Join(t.TempDir(), "nadi-agent")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}

	helperPath := filepath.Join(root, "usr", "libexec", "nadi", "nadi-provision")
	agentPath := filepath.Join(root, "opt", "nadi", "bin", "nadi-agent")

	store, journal, err := newProvisionJournal(filepath.Join(t.TempDir(), "initial-journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := installAgentAssetsJournaledAt(
		root,
		artifactPath,
		sha256SumHex(artifact),
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("install verified Agent assets: %v", err)
	}

	if err := os.Remove(helperPath); err != nil {
		t.Fatalf("simulate missing helper: %v", err)
	}

	recoveryStore, recoveryJournal, err := newProvisionJournal(filepath.Join(t.TempDir(), "recovery-journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := installAgentAssetsJournaledAt(
		root,
		artifactPath,
		sha256SumHex(artifact),
		os.Geteuid(),
		os.Getegid(),
		recoveryStore,
		&recoveryJournal,
	); err != nil {
		t.Fatalf("restore missing helper from verified artifact: %v", err)
	}

	for _, path := range []string{agentPath, helperPath} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read installed asset %s: %v", path, err)
		}
		if string(content) != string(artifact) {
			t.Fatalf("installed asset %s does not match the verified artifact", path)
		}
	}
}

func TestInstallAgentAssetsJournaledRefusesToReplaceCorruptHelper(t *testing.T) {
	root := t.TempDir()
	prepareAgentAssetDirectories(t, root)

	artifact := []byte("verified signed Agent release artifact")
	artifactPath := filepath.Join(t.TempDir(), "nadi-agent")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}

	helperPath := filepath.Join(root, "usr", "libexec", "nadi", "nadi-provision")
	store, journal, err := newProvisionJournal(filepath.Join(t.TempDir(), "initial-journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	if err := installAgentAssetsJournaledAt(
		root,
		artifactPath,
		sha256SumHex(artifact),
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("install verified Agent assets: %v", err)
	}

	corruptHelper := []byte("corrupt helper binary")
	if err := os.WriteFile(helperPath, corruptHelper, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(helperPath, 0755); err != nil {
		t.Fatal(err)
	}

	recoveryStore, recoveryJournal, err := newProvisionJournal(filepath.Join(t.TempDir(), "recovery-journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	err = installAgentAssetsJournaledAt(
		root,
		artifactPath,
		sha256SumHex(artifact),
		os.Geteuid(),
		os.Getegid(),
		recoveryStore,
		&recoveryJournal,
	)
	if err == nil {
		t.Fatal("recovery must refuse to replace a conflicting helper without an approved update operation")
	}

	actual, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(corruptHelper) {
		t.Fatal("recovery changed the pre-existing corrupt helper")
	}
}

func TestInstallAgentAssetsJournaledRejectsArtifactChecksumMismatchBeforeWrites(t *testing.T) {
	root := t.TempDir()
	prepareAgentAssetDirectories(t, root)

	artifact := []byte("staged Agent artifact")
	artifactPath := filepath.Join(t.TempDir(), "nadi-agent")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}

	store, journal, err := newProvisionJournal(filepath.Join(t.TempDir(), "checksum-journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	err = installAgentAssetsJournaledAt(
		root,
		artifactPath,
		sha256SumHex([]byte("different signed artifact")),
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	)
	if err == nil {
		t.Fatal("artifact checksum mismatch must be rejected")
	}

	agentPath := filepath.Join(root, "opt", "nadi", "bin", "nadi-agent")
	helperPath := filepath.Join(root, "usr", "libexec", "nadi", "nadi-provision")
	for _, path := range []string{agentPath, helperPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("checksum mismatch wrote asset %s: %v", path, err)
		}
	}
}

func prepareAgentAssetDirectories(t *testing.T, root string) {
	t.Helper()

	directories := []string{
		filepath.Join(root, "opt", "nadi", "bin"),
		filepath.Join(root, "usr", "libexec", "nadi"),
		filepath.Join(root, "etc", "nadi", "keys"),
		filepath.Join(root, "etc", "systemd", "system"),
	}

	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatalf("prepare temporary Agent asset directory %s: %v", directory, err)
		}
	}
}
