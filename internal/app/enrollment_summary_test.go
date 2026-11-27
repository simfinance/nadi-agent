package app

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nadi-agent/internal/config"
	"nadi-agent/internal/state"
)

func TestWriteEnrollmentSummaryOmitsCredentialMaterial(t *testing.T) {
	stateDirectory := t.TempDir()
	store, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}

	current := state.State{
		AgentInstanceID:  "agent-instance-1",
		CentralAgentID:   "central-agent-1",
		CentralServerID:  "central-server-1",
		AgentCredential:  "agent-secret-must-not-be-exported",
		EnrollmentStatus: "registered",
		CreatedAt:        time.Now().UTC(),
		Applications: []state.EnrolledApplication{
			{
				ApplicationID:         "application-1",
				ApplicationKey:        "application-key-1",
				ApplicationName:       "Example",
				Environment:           "production",
				RegistrationID:        "registration-1",
				ApplicationCredential: "application-secret-must-not-be-exported",
			},
		},
	}

	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	application := &App{
		config: config.Config{
			StateDir: stateDirectory,
		},
	}

	var output bytes.Buffer

	if err := application.WriteEnrollmentSummary(&output); err != nil {
		t.Fatal(err)
	}

	encoded := output.String()

	if strings.Contains(encoded, "agent-secret-must-not-be-exported") {
		t.Fatal("enrollment summary exposed the Agent credential")
	}

	if strings.Contains(encoded, "application-secret-must-not-be-exported") {
		t.Fatal("enrollment summary exposed an application credential")
	}

	var summary EnrollmentSummary

	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}

	if summary.ProtocolVersion != 1 || summary.EnrollmentStatus != "registered" {
		t.Fatalf("unexpected enrollment summary header: %#v", summary)
	}

	if len(summary.Applications) != 1 || summary.Applications[0].ApplicationID != "application-1" {
		t.Fatalf("unexpected enrollment application summary: %#v", summary.Applications)
	}

	var payload map[string]json.RawMessage

	if err := json.Unmarshal(output.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	expectedSummaryFields := []string{
		"protocol_version",
		"enrollment_status",
		"agent_instance_id",
		"agent_id",
		"server_id",
		"applications",
	}

	if len(payload) != len(expectedSummaryFields) {
		t.Fatalf("unexpected enrollment summary fields: %#v", payload)
	}

	for _, field := range expectedSummaryFields {
		if _, exists := payload[field]; !exists {
			t.Errorf("enrollment summary is missing allowed field %q", field)
		}
	}

	var applications []map[string]json.RawMessage

	if err := json.Unmarshal(payload["applications"], &applications); err != nil {
		t.Fatal(err)
	}

	expectedApplicationFields := []string{
		"application_id",
		"application_key",
		"application_name",
		"environment",
		"registration_id",
	}

	if len(applications) != 1 || len(applications[0]) != len(expectedApplicationFields) {
		t.Fatalf("unexpected enrollment application summary fields: %#v", applications)
	}

	for _, field := range expectedApplicationFields {
		if _, exists := applications[0][field]; !exists {
			t.Errorf("enrollment application summary is missing allowed field %q", field)
		}
	}
}

func TestWriteEnrollmentSummarySupportsMultipleApplicationsForOneAgent(t *testing.T) {
	stateDirectory := t.TempDir()
	store, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}

	current := state.State{
		AgentInstanceID:  "agent-instance-multi",
		CentralAgentID:   "central-agent-multi",
		CentralServerID:  "central-server-multi",
		EnrollmentStatus: "registered",
		Applications: []state.EnrolledApplication{
			{
				ApplicationID:   "application-1",
				ApplicationKey:  "application-key-1",
				ApplicationName: "Application One",
				Environment:     "production",
				RegistrationID:  "registration-1",
			},
			{
				ApplicationID:   "application-2",
				ApplicationKey:  "application-key-2",
				ApplicationName: "Application Two",
				Environment:     "staging",
				RegistrationID:  "registration-2",
			},
		},
	}

	if err := store.Save(current); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	application := &App{
		config: config.Config{
			StateDir: stateDirectory,
		},
	}

	var output bytes.Buffer

	if err := application.WriteEnrollmentSummary(&output); err != nil {
		t.Fatal(err)
	}

	var summary EnrollmentSummary

	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}

	if summary.AgentID != "central-agent-multi" {
		t.Fatalf("unexpected Agent identity: %q", summary.AgentID)
	}

	if len(summary.Applications) != 2 {
		t.Fatalf("expected two applications for one Agent, got %d", len(summary.Applications))
	}

	if summary.Applications[0].ApplicationID != "application-1" ||
		summary.Applications[1].ApplicationID != "application-2" {
		t.Fatalf("unexpected application identities: %#v", summary.Applications)
	}
}

func TestWriteEnrollmentSummaryRejectsUnregisteredAgent(t *testing.T) {
	stateDirectory := t.TempDir()
	store, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save(state.State{
		AgentInstanceID:  "agent-instance-1",
		EnrollmentStatus: "unregistered",
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	application := &App{
		config: config.Config{
			StateDir: stateDirectory,
		},
	}

	if err := application.WriteEnrollmentSummary(&bytes.Buffer{}); err == nil {
		t.Fatal("unregistered Agent must not produce an enrollment summary")
	}
}
