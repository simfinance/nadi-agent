package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"nadi-agent/internal/activation"
	"nadi-agent/internal/appmonitor"
	"nadi-agent/internal/appspool"
	"nadi-agent/internal/control"
	"nadi-agent/internal/servermetrics"
	"nadi-agent/internal/spool"
	"nadi-agent/internal/state"
	"nadi-agent/internal/telemetry"
)

const (
	telemetryTestApplicationID = "11111111-1111-4111-8111-111111111111"
	telemetryTestInstanceID    = "22222222-2222-4222-8222-222222222222"
)

func TestDeliverTelemetryAcknowledgesServerAndApplicationSpoolsAfterCentralACK(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++

		if request.Method != http.MethodPost || request.URL.Path != telemetry.EndpointPath {
			t.Errorf("unexpected telemetry request: %s %s", request.Method, request.URL.Path)
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer test-agent-credential" {
			t.Errorf("telemetry request did not use the Agent credential")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		var batch telemetry.Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Errorf("decode telemetry batch: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if batch.AgentInstanceID != telemetryTestInstanceID || len(batch.Records) != 1 {
			t.Errorf("unexpected telemetry batch identity or record count: %#v", batch)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		record := batch.Records[0]
		switch requestCount {
		case 1:
			if record.Stream != "server_metrics" || record.ApplicationID != nil {
				t.Errorf("server telemetry must be server-scoped and omit application_id: %#v", record)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		case 2:
			if record.Stream != "application_metrics" ||
				record.ApplicationID == nil ||
				*record.ApplicationID != telemetryTestApplicationID {
				t.Errorf("application telemetry has an invalid application scope: %#v", record)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			t.Errorf("unexpected additional telemetry request: %d", requestCount)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"success":         true,
				"batch_id":        batch.BatchID,
				"status":          "accepted",
				"record_count":    len(batch.Records),
				"accepted_count":  len(batch.Records),
				"duplicate_count": 0,
				"rejected_count":  0,
				"replayed":        false,
			},
		})
	}))
	defer server.Close()

	agent, agentState, decisions := newTelemetryDeliveryTestAgent(t, server)

	if err := agent.deliverTelemetry(context.Background(), agentState, true, decisions); err != nil {
		t.Fatalf("deliver server telemetry: %v", err)
	}

	serverRecords, err := agent.telemetrySpool.ReadBatch(10)
	if err != nil {
		t.Fatalf("read server spool after ACK: %v", err)
	}
	applicationRecords, err := agent.applicationSpool.ReadBatch(telemetryTestApplicationID, 10)
	if err != nil {
		t.Fatalf("read application spool after server ACK: %v", err)
	}
	if len(serverRecords) != 0 {
		t.Fatalf("server source record remained after valid ACK: %#v", serverRecords)
	}
	if len(applicationRecords) != 1 {
		t.Fatalf("application source record should remain until its own ACK: %#v", applicationRecords)
	}

	if err := agent.deliverTelemetry(context.Background(), agentState, true, decisions); err != nil {
		t.Fatalf("deliver application telemetry: %v", err)
	}

	applicationRecords, err = agent.applicationSpool.ReadBatch(telemetryTestApplicationID, 10)
	if err != nil {
		t.Fatalf("read application spool after ACK: %v", err)
	}
	if len(applicationRecords) != 0 {
		t.Fatalf("application source record remained after valid ACK: %#v", applicationRecords)
	}
	if requestCount != 2 {
		t.Fatalf("expected one server batch and one application batch, got %d requests", requestCount)
	}

	_, hasPending, err := agent.telemetrySender.PendingSources()
	if err != nil {
		t.Fatalf("inspect sender pending state: %v", err)
	}
	if hasPending {
		t.Fatal("sender pending batch remained after valid ACK and local completion")
	}
}

func TestDeliverTelemetryRetainsLocalSpoolsWhenCentralACKIsInvalid(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var batch telemetry.Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Errorf("decode telemetry batch: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"success": true,
			"data": map[string]any{
				"success":         true,
				"batch_id":        "33333333-3333-4333-8333-333333333333",
				"status":          "accepted",
				"record_count":    len(batch.Records),
				"accepted_count":  len(batch.Records),
				"duplicate_count": 0,
				"rejected_count":  0,
				"replayed":        false,
			},
		})
	}))
	defer server.Close()

	agent, agentState, decisions := newTelemetryDeliveryTestAgent(t, server)

	err := agent.deliverTelemetry(context.Background(), agentState, true, decisions)
	if err == nil {
		t.Fatal("expected mismatched Central batch ID to be rejected")
	}

	serverRecords, readErr := agent.telemetrySpool.ReadBatch(10)
	if readErr != nil {
		t.Fatalf("read server spool after invalid ACK: %v", readErr)
	}
	applicationRecords, readErr := agent.applicationSpool.ReadBatch(telemetryTestApplicationID, 10)
	if readErr != nil {
		t.Fatalf("read application spool after invalid ACK: %v", readErr)
	}
	if len(serverRecords) != 1 {
		t.Fatalf("server source record was removed without a valid ACK: %#v", serverRecords)
	}
	if len(applicationRecords) != 1 {
		t.Fatalf("application source record was removed without a valid ACK: %#v", applicationRecords)
	}

	pendingSources, hasPending, pendingErr := agent.telemetrySender.PendingSources()
	if pendingErr != nil {
		t.Fatalf("inspect pending sender batch: %v", pendingErr)
	}
	if !hasPending || len(pendingSources) != 1 {
		t.Fatalf("invalid ACK must leave the pending batch and source intact: %#v", pendingSources)
	}
}

func newTelemetryDeliveryTestAgent(
	t *testing.T,
	server *httptest.Server,
) (*App, state.State, map[string]activation.GateDecision) {
	t.Helper()

	now := time.Now().UTC()
	directory := t.TempDir()

	serverSpool, err := spool.Open(filepath.Join(directory, "server-spool"), spool.DefaultMaxBytes, spool.DefaultMaxRecords)
	if err != nil {
		t.Fatalf("open server spool: %v", err)
	}
	applicationSpool, err := appspool.Open(filepath.Join(directory, "application-spool"), appspool.DefaultMaxBytes, appspool.DefaultMaxRecords)
	if err != nil {
		t.Fatalf("open application spool: %v", err)
	}
	sender, err := telemetry.NewSenderWithHTTPClient(
		server.URL,
		filepath.Join(directory, "delivery"),
		server.Client(),
	)
	if err != nil {
		t.Fatalf("create telemetry sender: %v", err)
	}

	if _, err := serverSpool.Append("server-1", "central-agent-1", servermetrics.Snapshot{
		Timestamp: now,
		Hostname:  "test-server",
	}); err != nil {
		t.Fatalf("append server source record: %v", err)
	}
	if _, err := applicationSpool.Append("server-1", "central-agent-1", telemetryTestApplicationID, appmonitor.Snapshot{
		Timestamp: now,
		Health: appmonitor.EndpointResult{
			Status: appmonitor.StatusAvailable,
			Data:   json.RawMessage(`{"status":"ok"}`),
		},
	}); err != nil {
		t.Fatalf("append application source record: %v", err)
	}

	agent := &App{
		telemetrySpool:   serverSpool,
		applicationSpool: applicationSpool,
		telemetrySender:  sender,
		controlHTTP: &control.Client{
			Token: "test-agent-credential",
		},
	}

	agentState := state.State{
		CentralAgentID:  "central-agent-1",
		AgentInstanceID: telemetryTestInstanceID,
		Applications: []state.EnrolledApplication{
			{
				ApplicationID: telemetryTestApplicationID,
			},
		},
	}
	decisions := map[string]activation.GateDecision{
		telemetryTestApplicationID: {
			Enabled: true,
			Capabilities: []string{
				"server_metrics",
				appmonitor.CapabilityApplicationMetrics,
			},
		},
	}

	return agent, agentState, decisions
}
