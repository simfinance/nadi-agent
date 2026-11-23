package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSendPersistsBatchUntilLocalAcknowledgementCompletes(t *testing.T) {
	var received []Batch
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", request.Method)
		}
		if request.URL.Path != EndpointPath {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer credential" {
			t.Fatal("Agent credential header was not set")
		}
		if request.Header.Get("X-NADI-Agent-ID") != "agent-1" {
			t.Fatal("Agent ID header was not set")
		}
		if request.Header.Get("X-NADI-Request-ID") == "" {
			t.Fatal("request ID header was not set")
		}

		var batch Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		received = append(received, batch)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":{"success":true,"batch_id":"` + batch.BatchID + `","status":"accepted","record_count":1,"accepted_count":1,"duplicate_count":0,"rejected_count":0,"replayed":false}}`))
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()
	applicationID := "11111111-1111-4111-8111-111111111111"
	inputs := []InputRecord{{
		Stream:        "application_metrics",
		ObservedAt:    time.Now().UTC(),
		CollectedAt:   time.Now().UTC(),
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{"status":"available"}`),
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "source-event-1",
		},
	}}

	acknowledged, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", inputs)
	if err != nil {
		t.Fatalf("send batch: %v", err)
	}
	if len(acknowledged) != 1 || acknowledged[0].EventID != "source-event-1" {
		t.Fatalf("unexpected acknowledged sources: %#v", acknowledged)
	}
	if _, err := os.Stat(filepath.Join(directory, "pending-batch.json")); err != nil {
		t.Fatalf("pending batch removed before local spool acknowledgement: %v", err)
	}

	_, err = sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("replay pending batch: %v", err)
	}
	if len(received) != 2 || received[0].BatchID != received[1].BatchID || received[0].Records[0].RecordID != received[1].Records[0].RecordID {
		t.Fatal("retry did not preserve batch and record identifiers")
	}
	if received[0].Records[0].Sequence != 1 {
		t.Fatalf("unexpected first sequence: %d", received[0].Records[0].Sequence)
	}

	if err := sender.Complete(); err != nil {
		t.Fatalf("complete batch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "pending-batch.json")); !os.IsNotExist(err) {
		t.Fatalf("pending batch still exists after completion: %v", err)
	}
}

func TestBuildPendingUsesIndependentPersistentSequences(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	applicationID := "11111111-1111-4111-8111-111111111111"
	input := InputRecord{
		Stream:        "application_metrics",
		ObservedAt:    time.Now().UTC(),
		CollectedAt:   time.Now().UTC(),
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{}`),
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "source-event-sequence",
		},
	}

	first, err := sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{input})
	if err != nil {
		t.Fatalf("build first batch: %v", err)
	}
	if first.Batch.Records[0].Sequence != 1 {
		t.Fatalf("expected first sequence 1, got %d", first.Batch.Records[0].Sequence)
	}
	second, err := sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{input})
	if err != nil {
		t.Fatalf("build second batch: %v", err)
	}
	if second.Batch.Records[0].Sequence != 2 {
		t.Fatalf("expected second sequence 2, got %d", second.Batch.Records[0].Sequence)
	}
}

func TestBuildPendingRejectsApplicationStreamWithoutApplicationID(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	_, err = sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{{
		Stream: "application_metrics",
		Data:   json.RawMessage(`{}`),
	}})
	if err == nil {
		t.Fatal("expected application_id validation error")
	}
}

func TestBuildPendingRequiresServerScopeForNginxVhost(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	pending, err := sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{{
		Stream: "nginx_vhost_metrics",
		Data:   json.RawMessage(`{"requests":1}`),
		Source: Source{
			Kind:    "server",
			EventID: "server-event-1",
		},
	}})
	if err != nil {
		t.Fatalf("build Nginx vhost telemetry: %v", err)
	}
	if pending.Batch.Records[0].ApplicationID != nil {
		t.Fatal("server-scoped Nginx vhost telemetry must omit application_id")
	}
}

func TestBuildPendingRejectsUnsupportedStream(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	_, err = sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{{
		Stream: "invented_stream",
		Data:   json.RawMessage(`{}`),
	}})
	if err == nil {
		t.Fatal("expected unsupported stream validation error")
	}
}

func TestBuildPendingRejectsServerMetricsWithApplicationID(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	applicationID := "11111111-1111-4111-8111-111111111111"
	_, err = sender.buildPending("22222222-2222-4222-8222-222222222222", []InputRecord{{
		Stream:        "server_metrics",
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{}`),
	}})
	if err == nil {
		t.Fatal("expected server_metrics scope validation error")
	}
}

func TestRequiredCapabilityMatchesCentralV11StreamMatrix(t *testing.T) {
	expected := map[string]string{
		"server_metrics":       "server_metrics",
		"nginx_metrics":        "server_metrics",
		"nginx_vhost_metrics":  "server_metrics",
		"nginx_error_logs":     "system_logs",
		"application_metrics":  "application_metrics",
		"application_logs":     "application_logs",
		"database_metrics":     "database_monitoring",
		"database_connections": "database_monitoring",
		"queue_metrics":        "queue_monitoring",
		"queue_jobs":           "queue_monitoring",
		"scheduler_metrics":    "scheduler_monitoring",
		"scheduler_events":     "scheduler_monitoring",
	}

	for stream, capability := range expected {
		actual, found := RequiredCapability(stream)
		if !found || actual != capability {
			t.Fatalf("RequiredCapability(%q) = %q, %t; want %q, true", stream, actual, found, capability)
		}
	}

	for _, stream := range []string{
		"nginx_access_logs",
		"application_events",
		"nginx_http_requests",
		"application_http_requests",
		"application_http_errors",
	} {
		if _, found := RequiredCapability(stream); found {
			t.Fatalf("legacy stream %q must not be allowed", stream)
		}
	}
}

func TestBuildPendingDoesNotMixApplicationScopes(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}

	applicationA := "11111111-1111-4111-8111-111111111111"
	applicationB := "33333333-3333-4333-8333-333333333333"
	inputs := []InputRecord{
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationA,
			Data:          json.RawMessage(`{}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationA,
				EventID:       "event-a",
			},
		},
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationB,
			Data:          json.RawMessage(`{}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationB,
				EventID:       "event-b",
			},
		},
	}

	pending, err := sender.buildPending("22222222-2222-4222-8222-222222222222", inputs)
	if err != nil {
		t.Fatalf("build scoped batch: %v", err)
	}
	if len(pending.Batch.Records) != 1 {
		t.Fatalf("expected one record in first application scope batch, got %d", len(pending.Batch.Records))
	}
	if *pending.Batch.Records[0].ApplicationID != applicationA {
		t.Fatal("first batch crossed the application scope boundary")
	}
}

func TestBuildPendingCapsBatchAtFiveHundredWithoutAcknowledgingRemainder(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}

	applicationID := "11111111-1111-4111-8111-111111111111"
	inputs := make([]InputRecord, MaximumBatchRecords+1)
	for index := range inputs {
		inputs[index] = InputRecord{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       fmt.Sprintf("event-%d", index),
			},
		}
	}

	pending, err := sender.buildPending("22222222-2222-4222-8222-222222222222", inputs)
	if err != nil {
		t.Fatalf("build bounded batch: %v", err)
	}
	if len(pending.Batch.Records) != MaximumBatchRecords || len(pending.Sources) != MaximumBatchRecords {
		t.Fatalf("expected exactly %d records and sources, got %d and %d", MaximumBatchRecords, len(pending.Batch.Records), len(pending.Sources))
	}
}
