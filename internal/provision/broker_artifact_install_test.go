package provision

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"nadi-agent/internal/handoffbroker"
)

func TestInstallBrokerArtifactsWritesOnlyValidatedDestinations(t *testing.T) {
	root := t.TempDir()
	uid := os.Getuid()
	gid := os.Getgid()

	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "app-one",
				BasePath:            "/srv/www/app-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	mapping, err := encodeBrokerMapping(config)
	if err != nil {
		t.Fatal(err)
	}

	dropIn, err := BuildBrokerDropIn(config)
	if err != nil {
		t.Fatal(err)
	}

	if err := installBrokerArtifactsAt(root, config, mapping, dropIn, uid, gid); err != nil {
		t.Fatalf("valid broker artifacts were rejected: %v", err)
	}

	configDirectoryInfo, err := os.Stat(filepath.Join(root, "etc", "nadi"))
	if err != nil {
		t.Fatal(err)
	}
	if configDirectoryInfo.Mode().Perm() != 0750 {
		t.Fatalf("expected /etc/nadi mode 0750, got %04o", configDirectoryInfo.Mode().Perm())
	}

	mappingPath := filepath.Join(root, "etc", "nadi", "bridge-mappings.json")
	mappingInfo, err := os.Stat(mappingPath)
	if err != nil {
		t.Fatal(err)
	}

	if mappingInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected mapping mode 0600, got %04o", mappingInfo.Mode().Perm())
	}

	dropInPath := filepath.Join(root, "etc", "systemd", "system", "nadi-handoff-broker.service.d", "bridge-credentials.conf")
	dropInBytes, err := os.ReadFile(dropInPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(dropInBytes) != dropIn || strings.Contains(string(dropInBytes), "ReadWritePaths=/var/lib/nadi-bridge\n") {
		t.Fatal("installed systemd drop-in does not preserve the exact application write scope")
	}

	bridgeRoot := filepath.Join(root, "var", "lib", "nadi-bridge")
	bridgeRootInfo, err := os.Stat(bridgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if bridgeRootInfo.Mode().Perm() != 0711 {
		t.Fatalf("expected Bridge root mode 0711, got %04o", bridgeRootInfo.Mode().Perm())
	}

	varLibInfo, err := os.Stat(filepath.Join(root, "var", "lib"))
	if err != nil {
		t.Fatal(err)
	}
	if varLibInfo.Mode().Perm() != 0755 {
		t.Fatalf("expected system /var/lib mode 0755, got %04o", varLibInfo.Mode().Perm())
	}

	credentialDirectory := filepath.Join(bridgeRoot, "00000000-0000-4000-8000-000000000001")
	directoryInfo, err := os.Stat(credentialDirectory)
	if err != nil {
		t.Fatal(err)
	}

	if directoryInfo.Mode().Perm() != 0711 {
		t.Fatalf("expected credential directory mode 0711, got %04o", directoryInfo.Mode().Perm())
	}

	stat, ok := directoryInfo.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatal("credential directory ownership does not match the expected owner")
	}
}

func TestWriteOwnedAtomicFileRefusesUnapprovedReplacement(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "managed.json")
	original := []byte("{\"version\":1}\n")

	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeOwnedAtomicFile(path, []byte("{\"version\":2}\n"), 0600, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("existing managed file must not be overwritten without an approved update")
	}

	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(original) {
		t.Fatal("existing managed file changed after rejected replacement")
	}
}

func TestWriteOwnedAtomicFileAcceptsIdenticalExistingFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "managed.json")
	content := []byte("{\"version\":1}\n")

	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	if err := writeOwnedAtomicFile(path, content, 0600, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("identical managed file should be idempotent: %v", err)
	}
}

func TestInstallBrokerArtifactsRejectsMismatchedDropIn(t *testing.T) {
	root := t.TempDir()
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "app-one",
				BasePath:            "/srv/www/app-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000/000000000001.json",
			},
		},
	}

	if err := installBrokerArtifactsAt(root, config, []byte("{}\n"), "[Service]\n", os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("mismatched artifacts must be rejected before filesystem changes")
	}

	if _, err := os.Stat(filepath.Join(root, "etc")); !os.IsNotExist(err) {
		t.Fatal("invalid artifacts must be rejected before creating directories")
	}
}

func TestEnsureDirectoryTreeRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	uid := os.Getuid()
	gid := os.Getgid()

	linkTarget := filepath.Join(root, "target")
	if err := os.Mkdir(linkTarget, 0755); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(root, "linked")
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}

	if err := ensureDirectoryTree(root, filepath.Join(linkPath, "child"), 0755, uid, gid); err == nil {
		t.Fatal("symlink path component must be rejected")
	}
}

func TestVerifyBrokerArtifactDirectoriesRejectsSymlinkAncestor(t *testing.T) {
	root := t.TempDir()
	uid := os.Getuid()
	gid := os.Getgid()

	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "app-one",
				BasePath:            "/srv/www/app-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	directories := map[string]os.FileMode{
		filepath.Join(root, "var", "lib", "nadi-bridge"):                                       0711,
		filepath.Join(root, "var", "lib", "nadi-bridge", config.Applications[0].ApplicationID): 0711,
		filepath.Join(root, "etc", "nadi"):                                                     0750,
		filepath.Join(root, "etc", "systemd", "system", "nadi-handoff-broker.service.d"):       0755,
	}

	for directory, mode := range directories {
		if err := os.MkdirAll(directory, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
	}

	systemdPath := filepath.Join(root, "etc", "systemd")
	systemdTarget := filepath.Join(root, "etc", "systemd-target")
	if err := os.Rename(systemdPath, systemdTarget); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(systemdTarget, systemdPath); err != nil {
		t.Fatal(err)
	}

	if err := verifyBrokerArtifactDirectories(config, root, uid, gid); err == nil {
		t.Fatal("verification must reject a symlink in a managed directory's ancestry")
	}
}

func TestInstallBrokerArtifactsJournaledRollsBackWhenDropInAncestorIsSymlinked(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}

	etcDirectory := filepath.Join(root, "etc")
	if err := os.Mkdir(etcDirectory, 0755); err != nil {
		t.Fatal(err)
	}

	outsideDirectory := filepath.Join(base, "outside")
	if err := os.Mkdir(outsideDirectory, 0755); err != nil {
		t.Fatal(err)
	}

	systemdPath := filepath.Join(etcDirectory, "systemd")
	if err := os.Symlink(outsideDirectory, systemdPath); err != nil {
		t.Fatal(err)
	}

	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "app-one",
				BasePath:            "/srv/www/app-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	mapping, err := encodeBrokerMapping(config)
	if err != nil {
		t.Fatal(err)
	}

	dropIn, err := BuildBrokerDropIn(config)
	if err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(base, "provisioning-journal.json")
	store, journal, err := newProvisionJournalForOperation(journalPath, "restore_agent")
	if err != nil {
		t.Fatal(err)
	}

	err = installBrokerArtifactsJournaledAt(
		root,
		config,
		mapping,
		dropIn,
		os.Getuid(),
		os.Getgid(),
		store,
		&journal,
	)
	if err == nil {
		t.Fatal("journaled Bridge installation must reject a symlinked systemd ancestor")
	}

	if err := store.Rollback(&journal, []string{root}); err != nil {
		t.Fatalf("rollback partial Bridge installation: %v", err)
	}

	mappingPath := filepath.Join(root, "etc", "nadi", "bridge-mappings.json")
	if _, err := os.Lstat(mappingPath); !os.IsNotExist(err) {
		t.Fatalf("partial Bridge mapping was not rolled back: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(root, "var")); !os.IsNotExist(err) {
		t.Fatalf("partial Bridge directories were not rolled back: %v", err)
	}

	systemdMetadata, err := os.Lstat(systemdPath)
	if err != nil {
		t.Fatalf("pre-existing systemd symlink was not preserved: %v", err)
	}
	if systemdMetadata.Mode()&os.ModeSymlink == 0 {
		t.Fatal("pre-existing systemd path was unexpectedly replaced")
	}

	persistedJournal, err := store.Load()
	if err != nil {
		t.Fatalf("load completed rollback journal: %v", err)
	}
	if persistedJournal.Phase != "rolled_back" {
		t.Fatalf("partial Bridge rollback did not reach rolled_back: %q", persistedJournal.Phase)
	}
}
