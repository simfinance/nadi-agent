package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nadi-agent/internal/handoffbroker"
)

func TestBuildBridgeApplicationConfigurationsCreatesIsolatedFiles(t *testing.T) {
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "application-one",
				BasePath:            "/srv/www/application-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000002",
				ApplicationKey:      "application-two",
				BasePath:            "/srv/www/application-two",
				RuntimeUID:          1002,
				RuntimeGID:          1002,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000002/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000002.json",
			},
		},
	}

	artifacts, err := BuildBridgeApplicationConfigurations(
		config,
		[]string{"203.0.113.10", "2001:db8::1"},
	)
	if err != nil {
		t.Fatalf("build Bridge application configurations: %v", err)
	}
	if len(artifacts) != 2 {
		t.Fatalf("expected two per-application configuration files, got %d", len(artifacts))
	}

	for index, application := range config.Applications {
		digest := sha256.Sum256([]byte(application.BasePath))
		expectedPath := filepath.Join(
			bridgeApplicationConfigDirectory,
			hex.EncodeToString(digest[:])+".json",
		)
		if artifacts[index].Path != expectedPath {
			t.Fatalf("unexpected configuration path: got %q want %q", artifacts[index].Path, expectedPath)
		}
		if artifacts[index].GID != application.RuntimeGID {
			t.Fatalf("configuration GID does not match application runtime: got %d want %d", artifacts[index].GID, application.RuntimeGID)
		}

		var configuration bridgeApplicationConfiguration
		if err := json.Unmarshal(artifacts[index].Content, &configuration); err != nil {
			t.Fatalf("decode generated Bridge configuration: %v", err)
		}
		if configuration.SchemaVersion != 1 ||
			!configuration.Enabled ||
			configuration.ApplicationID != application.ApplicationID ||
			configuration.ApplicationKey != application.ApplicationKey {
			t.Fatalf("generated Bridge configuration has the wrong application identity: %+v", configuration)
		}
		if len(configuration.AllowedIPs) != 2 ||
			configuration.AllowedIPs[0] != "2001:db8::1" ||
			configuration.AllowedIPs[1] != "203.0.113.10" {
			t.Fatalf("Central source IPs were not normalized and sorted: %+v", configuration.AllowedIPs)
		}
		if configuration.CredentialFile != application.CredentialFile ||
			configuration.ActivationStateFile != application.ActivationStateFile {
			t.Fatalf("generated Bridge configuration changed fixed paths: %+v", configuration)
		}
	}
}

func TestBuildBridgeApplicationConfigurationsRejectsSharedRuntimeGID(t *testing.T) {
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "application-one",
				BasePath:            "/srv/www/application-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000002",
				ApplicationKey:      "application-two",
				BasePath:            "/srv/www/application-two",
				RuntimeUID:          1002,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000002/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000002.json",
			},
		},
	}

	if _, err := BuildBridgeApplicationConfigurations(config, []string{"203.0.113.10"}); err == nil {
		t.Fatal("shared PHP-FPM runtime GID must be rejected")
	}
}

func TestBuildBridgeApplicationConfigurationsRejectsCIDRAllowlist(t *testing.T) {
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "application-one",
				BasePath:            "/srv/www/application-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if _, err := BuildBridgeApplicationConfigurations(config, []string{"203.0.113.0/24"}); err == nil {
		t.Fatal("CIDR ranges must not be accepted as exact source IP addresses")
	}
}

func TestInstallBridgeApplicationConfigurationsJournaledAtVerifiesAndRollsBack(t *testing.T) {
	root := t.TempDir()
	config := testBridgeApplicationConfiguration()
	centralSourceIPs := []string{"203.0.113.10"}
	store, journal, err := newProvisionJournalForOperation(
		filepath.Join(root, "journal.json"),
		"restore_agent",
	)
	if err != nil {
		t.Fatalf("create enrollment journal: %v", err)
	}

	if err := installBridgeApplicationConfigurationsJournaledAt(
		root,
		config,
		centralSourceIPs,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("install journaled Bridge application configuration: %v", err)
	}

	if err := verifyBridgeApplicationConfigurationsAt(
		config,
		centralSourceIPs,
		root,
		os.Geteuid(),
		os.Getegid(),
	); err != nil {
		t.Fatalf("verify journaled Bridge application configuration: %v", err)
	}

	artifacts, err := BuildBridgeApplicationConfigurations(config, centralSourceIPs)
	if err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(
		root,
		strings.TrimPrefix(artifacts[0].Path, string(os.PathSeparator)),
	)
	metadata, err := os.Stat(configurationPath)
	if err != nil {
		t.Fatalf("inspect installed Bridge application configuration: %v", err)
	}
	if metadata.Mode().Perm() != bridgeApplicationConfigFileMode {
		t.Fatalf("unexpected Bridge application configuration mode: %o", metadata.Mode().Perm())
	}

	if err := store.Rollback(&journal, []string{root}); err != nil {
		t.Fatalf("rollback Bridge application configuration: %v", err)
	}
	if _, err := os.Lstat(configurationPath); !os.IsNotExist(err) {
		t.Fatalf("Bridge application configuration remains after rollback: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "var")); !os.IsNotExist(err) {
		t.Fatalf("Bridge application configuration directory remains after rollback: %v", err)
	}
}

func TestBridgeApplicationConfigurationRestoreVerificationPreservesExternalChange(t *testing.T) {
	root := t.TempDir()
	config := testBridgeApplicationConfiguration()
	centralSourceIPs := []string{"203.0.113.10"}
	store, journal, err := newProvisionJournalForOperation(
		filepath.Join(root, "journal.json"),
		"restore_agent",
	)
	if err != nil {
		t.Fatalf("create RESTORE journal: %v", err)
	}

	if err := installBridgeApplicationConfigurationsJournaledAt(
		root,
		config,
		centralSourceIPs,
		os.Geteuid(),
		os.Getegid(),
		store,
		&journal,
	); err != nil {
		t.Fatalf("install RESTORE Bridge application configuration: %v", err)
	}

	artifacts, err := BuildBridgeApplicationConfigurations(config, centralSourceIPs)
	if err != nil {
		t.Fatal(err)
	}
	configurationPath := filepath.Join(
		root,
		strings.TrimPrefix(artifacts[0].Path, string(os.PathSeparator)),
	)
	original, err := os.ReadFile(configurationPath)
	if err != nil {
		t.Fatalf("read installed Bridge application configuration: %v", err)
	}
	externalChange := bytes.Replace(
		original,
		[]byte("application-one"),
		[]byte("external-change"),
		1,
	)
	if bytes.Equal(original, externalChange) {
		t.Fatal("test fixture did not change the Bridge application configuration")
	}
	if err := os.WriteFile(configurationPath, externalChange, bridgeApplicationConfigFileMode); err != nil {
		t.Fatalf("simulate external configuration change: %v", err)
	}
	if err := os.Chmod(configurationPath, bridgeApplicationConfigFileMode); err != nil {
		t.Fatalf("restore external configuration permissions: %v", err)
	}

	if err := verifyBridgeApplicationConfigurationsAt(
		config,
		centralSourceIPs,
		root,
		os.Geteuid(),
		os.Getegid(),
	); err == nil {
		t.Fatal("RESTORE verification must reject an externally changed Bridge configuration")
	}

	if err := store.Rollback(&journal, []string{root}); err == nil {
		t.Fatal("rollback must refuse to remove an externally changed Bridge configuration")
	}
	if journal.Phase != "rollback_required" {
		t.Fatalf("expected rollback_required after external change, got %q", journal.Phase)
	}

	preserved, err := os.ReadFile(configurationPath)
	if err != nil {
		t.Fatalf("externally changed configuration was not preserved: %v", err)
	}
	if !bytes.Equal(preserved, externalChange) {
		t.Fatal("rollback changed the externally modified Bridge configuration")
	}
}

func testBridgeApplicationConfiguration() handoffbroker.Config {
	runtimeGID := os.Getegid()
	if runtimeGID == 0 {
		runtimeGID = 1001
	}

	applicationID := "00000000-0000-4000-8000-000000000001"

	return handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       applicationID,
				ApplicationKey:      "application-one",
				BasePath:            "/srv/www/application-one",
				RuntimeUID:          1001,
				RuntimeGID:          runtimeGID,
				CredentialFile:      "/var/lib/nadi-bridge/" + applicationID + "/credential",
				ActivationStateFile: "/run/nadi/bridge-state/" + applicationID + ".json",
			},
		},
	}
}

func TestBuildBridgeApplicationConfigurationsRejectsMissingAllowlist(t *testing.T) {
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "application-one",
				BasePath:            "/srv/www/application-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if _, err := BuildBridgeApplicationConfigurations(config, nil); err == nil {
		t.Fatal("empty Central source-IP allowlist must fail closed")
	}
}
