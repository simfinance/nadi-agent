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

	mappingPath := filepath.Join(root, "etc", "nadi-agent", "bridge-mappings.json")
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
