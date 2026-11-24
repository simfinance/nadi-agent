package provision

import (
	"encoding/json"
	"strings"
	"testing"

	"nadi-agent/internal/handoffbroker"
)

func TestBuildBrokerArtifactsReconcilesEveryApplication(t *testing.T) {
	request := ProvisionRequest{
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "app-one",
				BasePath:       "/srv/www/app-one",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
			{
				ApplicationKey: "app-two",
				BasePath:       "/srv/www/app-two",
				RuntimeUID:     1002,
				RuntimeGID:     1002,
			},
		},
	}

	summary := enrollmentSummary{
		ProtocolVersion:  1,
		EnrollmentStatus: "registered",
		AgentInstanceID:  "agent-instance",
		AgentID:          "central-agent",
		ServerID:         "central-server",
		Applications: []enrollmentSummaryApplication{
			{
				ApplicationID:   "00000000-0000-4000-8000-000000000002",
				ApplicationKey:  "app-two",
				ApplicationName: "Application Two",
				Environment:     "staging",
				RegistrationID:  "registration-two",
			},
			{
				ApplicationID:   "00000000-0000-4000-8000-000000000001",
				ApplicationKey:  "app-one",
				ApplicationName: "Application One",
				Environment:     "production",
				RegistrationID:  "registration-one",
			},
		},
	}

	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}

	config, mappingJSON, dropIn, err := BuildBrokerArtifacts(900, 900, request, summaryJSON)
	if err != nil {
		t.Fatalf("valid enrollment summary was rejected: %v", err)
	}

	if len(config.Applications) != 2 {
		t.Fatalf("expected two broker mappings, got %d", len(config.Applications))
	}

	if config.Applications[0].ApplicationID != "00000000-0000-4000-8000-000000000001" {
		t.Fatalf("expected mappings to be sorted by application ID, got %q", config.Applications[0].ApplicationID)
	}

	if !strings.Contains(string(mappingJSON), "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential") {
		t.Fatal("mapping JSON does not contain the fixed external credential destination")
	}

	if !strings.Contains(dropIn, "ReadWritePaths=/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001\n") ||
		!strings.Contains(dropIn, "ReadWritePaths=/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000002\n") {
		t.Fatalf("systemd drop-in does not contain both exact application directories: %s", dropIn)
	}

	if strings.Contains(dropIn, "ReadWritePaths=/var/lib/nadi-bridge\n") {
		t.Fatal("systemd drop-in must not grant access to the entire Bridge data root")
	}
}

func TestBuildBrokerArtifactsRejectsMissingApplication(t *testing.T) {
	request := ProvisionRequest{
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "app-one",
				BasePath:       "/srv/www/app-one",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
		},
	}

	summary := []byte(`{
		"protocol_version": 1,
		"enrollment_status": "registered",
		"agent_instance_id": "agent-instance",
		"agent_id": "central-agent",
		"server_id": "central-server",
		"applications": []
	}`)

	if _, _, _, err := BuildBrokerArtifacts(900, 900, request, summary); err == nil {
		t.Fatal("summary missing a local application must be rejected")
	}
}

func TestBuildBrokerArtifactsRejectsUnknownSummaryFields(t *testing.T) {
	request := ProvisionRequest{
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "app-one",
				BasePath:       "/srv/www/app-one",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
		},
	}

	summary := []byte(`{
		"protocol_version": 1,
		"enrollment_status": "registered",
		"agent_instance_id": "agent-instance",
		"agent_id": "central-agent",
		"server_id": "central-server",
		"unexpected_secret": "must-not-be-accepted",
		"applications": [
			{
				"application_id": "00000000-0000-4000-8000-000000000001",
				"application_key": "app-one"
			}
		]
	}`)

	if _, _, _, err := BuildBrokerArtifacts(900, 900, request, summary); err == nil {
		t.Fatal("unknown enrollment summary fields must be rejected")
	}
}

func TestBuildBrokerDropInRejectsInvalidMapping(t *testing.T) {
	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      900,
		AgentGID:      900,
		Applications: []handoffbroker.Mapping{
			{
				ApplicationID:       "not-a-uuid",
				ApplicationKey:      "app-one",
				BasePath:            "/srv/www/app-one",
				RuntimeUID:          1001,
				RuntimeGID:          1001,
				CredentialFile:      "/var/lib/nadi-bridge/not-a-uuid/credential",
				ActivationStateFile: "/run/nadi/bridge-state/not-a-uuid.json",
			},
		},
	}

	if _, err := BuildBrokerDropIn(config); err == nil {
		t.Fatal("invalid broker mapping must not produce a systemd drop-in")
	}
}
