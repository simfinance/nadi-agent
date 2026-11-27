package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
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
