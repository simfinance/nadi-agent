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
		AgentInstanceID: "agent-instance-1",
		CentralAgentID: "central-agent-1",
		CentralServerID: "central-server-1",
		AgentCredential: "agent-secret-must-not-be-exported",
		EnrollmentStatus: "registered",
		CreatedAt: time.Now().UTC(),
		Applications: []state.EnrolledApplication{
			{
				ApplicationID: "application-1",
				ApplicationKey: "application-key-1",
				ApplicationName: "Example",
				Environment: "production",
				RegistrationID: "registration-1",
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
}

func TestWriteEnrollmentSummaryRejectsUnregisteredAgent(t *testing.T) {
	stateDirectory := t.TempDir()
	store, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save(state.State{
		AgentInstanceID: "agent-instance-1",
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
