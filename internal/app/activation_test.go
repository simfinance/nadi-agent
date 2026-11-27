package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nadi-agent/internal/activation"
	"nadi-agent/internal/config"
	"nadi-agent/internal/control"
	"nadi-agent/internal/state"
)

func TestActivationGrantAcknowledgementPersistsBeforeDeliveryAndRetries(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Activation Grant key: %v", err)
	}

	publicKeyPath := filepath.Join(t.TempDir(), "activation-public.pem")
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal Activation Grant public key: %v", err)
	}
	if err := os.WriteFile(
		publicKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}),
		0600,
	); err != nil {
		t.Fatalf("write Activation Grant public key: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	payload := activation.Payload{
		GrantID:           "grant-activation-1",
		GrantVersion:      1,
		KeyID:             "test-activation-key",
		RegistrationID:    "registration-1",
		ApplicationID:     "application-1",
		AgentID:           "agent-1",
		ServerID:          "server-1",
		IssuedAt:          now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt:         now.Add(time.Hour).Format(time.RFC3339Nano),
		Capabilities:      []string{"application_metrics"},
		MonitoringEnabled: true,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal Activation Grant payload: %v", err)
	}
	canonicalPayload, err := activation.CanonicalJSON(payloadBytes)
	if err != nil {
		t.Fatalf("canonicalize Activation Grant payload: %v", err)
	}

	grant := control.ActivationGrant{
		GrantID:      payload.GrantID,
		GrantVersion: payload.GrantVersion,
		KeyID:        payload.KeyID,
		Payload:      payloadBytes,
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonicalPayload)),
	}
	polledApplication := control.Application{
		ApplicationID:      payload.ApplicationID,
		RegistrationStatus: "approved",
		ActivationStatus:   "active",
		MonitoringStatus:   "active",
		MonitoringEnabled:  true,
		ActivationGrant:    &grant,
	}

	stateDirectory := t.TempDir()
	acknowledgementAttempts := 0
	var firstRequestID string

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Errorf("expected POST acknowledgement, got %s", request.Method)
		}
		if request.URL.Path != "/api/v1/nadi/agent/activation-grants/"+grant.GrantID+"/ack" {
			t.Errorf("unexpected acknowledgement path: %s", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer agent-secret" {
			t.Error("acknowledgement did not use the Agent credential")
		}

		var acknowledgement control.AcknowledgementRequest
		if err := json.NewDecoder(request.Body).Decode(&acknowledgement); err != nil {
			t.Errorf("decode acknowledgement request: %v", err)
			http.Error(writer, "invalid acknowledgement", http.StatusBadRequest)
			return
		}

		stateBytes, err := os.ReadFile(filepath.Join(stateDirectory, "state.json"))
		if err != nil {
			t.Errorf("read persisted state during acknowledgement: %v", err)
			http.Error(writer, "state unavailable", http.StatusInternalServerError)
			return
		}

		var persisted state.State
		if err := json.Unmarshal(stateBytes, &persisted); err != nil {
			t.Errorf("decode persisted state during acknowledgement: %v", err)
			http.Error(writer, "state invalid", http.StatusInternalServerError)
			return
		}
		if len(persisted.ActivationGrants) != 1 {
			t.Errorf("expected verified grant to be persisted before acknowledgement, got %d", len(persisted.ActivationGrants))
		}
		if len(persisted.PendingAcknowledgements) != 1 {
			t.Errorf("expected pending acknowledgement to be persisted before delivery, got %d", len(persisted.PendingAcknowledgements))
		} else if persisted.PendingAcknowledgements[0].RequestID != acknowledgement.RequestID {
			t.Error("delivered request ID does not match the persisted pending acknowledgement")
		}
		if len(persisted.ActivationGrants) == 1 && persisted.ActivationGrants[0].Acknowledged {
			t.Error("grant must remain unacknowledged until Central accepts the acknowledgement")
		}
		if acknowledgement.ApplicationID != payload.ApplicationID || acknowledgement.Result != "success" {
			t.Errorf("unexpected acknowledgement payload: %+v", acknowledgement)
		}

		acknowledgementAttempts++
		if acknowledgementAttempts == 1 {
			firstRequestID = acknowledgement.RequestID
			http.Error(writer, "temporary Central failure", http.StatusServiceUnavailable)
			return
		}
		if acknowledgement.RequestID != firstRequestID {
			t.Errorf("retry changed the acknowledgement request ID: first=%s retry=%s", firstRequestID, acknowledgement.RequestID)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"message":"acknowledgement accepted"}`))
	}))
	defer server.Close()

	store, err := state.Open(stateDirectory)
	if err != nil {
		t.Fatalf("open Agent state: %v", err)
	}
	defer store.Close()

	initialState := state.State{
		AgentInstanceID:  "instance-1",
		CentralAgentID:   payload.AgentID,
		CentralServerID:  payload.ServerID,
		EnrollmentStatus: "registered",
		Applications: []state.EnrolledApplication{
			{
				ApplicationID:  payload.ApplicationID,
				RegistrationID: payload.RegistrationID,
			},
		},
	}
	if err := store.Save(initialState); err != nil {
		t.Fatalf("save initial Agent state: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	application := New(config.Config{
		CentralURL:              server.URL,
		AgentToken:              "agent-secret",
		ActivationPublicKeyPath: publicKeyPath,
		ActivationKeyID:         payload.KeyID,
		HTTPTimeout:             time.Second,
		StateDir:                stateDirectory,
	}, logger)
	application.controlHTTP.HTTP = server.Client()

	current, err := store.Load()
	if err != nil {
		t.Fatalf("load initial Agent state: %v", err)
	}
	pollData := control.PollData{
		Applications: []control.Application{polledApplication},
	}

	if err := application.processActivationGrants(context.Background(), store, current, pollData); err != nil {
		t.Fatalf("process verified Activation Grant: %v", err)
	}

	pendingState, err := store.Load()
	if err != nil {
		t.Fatalf("load state after failed acknowledgement: %v", err)
	}
	if len(pendingState.PendingAcknowledgements) != 1 {
		t.Fatalf("expected one durable pending acknowledgement, got %d", len(pendingState.PendingAcknowledgements))
	}
	if len(pendingState.ActivationGrants) != 1 || pendingState.ActivationGrants[0].Acknowledged {
		t.Fatal("grant must remain persisted but unacknowledged after Central failure")
	}

	verifier, err := activation.NewVerifier(publicKeyPath, payload.KeyID)
	if err != nil {
		t.Fatalf("initialize Activation Grant verifier: %v", err)
	}
	decision := verifier.Evaluate(
		pendingState.Applications[0],
		&polledApplication,
		pendingState,
		now,
	)
	if decision.Enabled {
		t.Fatal("monitoring gate opened before Central accepted the acknowledgement")
	}

	if err := application.processActivationGrants(context.Background(), store, pendingState, pollData); err != nil {
		t.Fatalf("retry pending Activation Grant acknowledgement: %v", err)
	}

	acceptedState, err := store.Load()
	if err != nil {
		t.Fatalf("load state after accepted acknowledgement: %v", err)
	}
	if len(acceptedState.PendingAcknowledgements) != 0 {
		t.Fatalf("expected pending acknowledgement queue to be empty, got %d", len(acceptedState.PendingAcknowledgements))
	}
	if len(acceptedState.ActivationGrants) != 1 || !acceptedState.ActivationGrants[0].Acknowledged {
		t.Fatal("Central-accepted acknowledgement was not persisted")
	}
	if acknowledgementAttempts != 2 {
		t.Fatalf("expected one failed delivery and one retry, got %d attempts", acknowledgementAttempts)
	}

	decision = verifier.Evaluate(
		acceptedState.Applications[0],
		&polledApplication,
		acceptedState,
		now,
	)
	if !decision.Enabled {
		t.Fatalf("monitoring gate did not open after accepted acknowledgement: %s", decision.Reason)
	}
	if decision.GrantID != grant.GrantID {
		t.Fatalf("unexpected active grant ID: %s", decision.GrantID)
	}
}
