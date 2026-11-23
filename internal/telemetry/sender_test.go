package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

func TestSendQuarantinesPermanentCentralStatuses(t *testing.T) {
	for _, statusCode := range []int{
		http.StatusForbidden,
		http.StatusConflict,
		http.StatusGone,
		http.StatusUnprocessableEntity,
	} {
		t.Run(fmt.Sprintf("http_%d", statusCode), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(statusCode)
				_, _ = writer.Write([]byte(`{"success":false,"message":"permanent rejection"}`))
			}))
			defer server.Close()

			directory := t.TempDir()
			sender, err := NewSender(server.URL, directory, time.Second)
			if err != nil {
				t.Fatalf("create sender: %v", err)
			}
			sender.client = server.Client()

			applicationID := "11111111-1111-4111-8111-111111111111"
			sources, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", []InputRecord{{
				Stream:        "application_metrics",
				ApplicationID: &applicationID,
				Data:          json.RawMessage(`{}`),
				Source: Source{
					Kind:          "application",
					ApplicationID: applicationID,
					EventID:       "event-permanent",
				},
			}})
			if err != nil {
				t.Fatalf("send permanent rejection: %v", err)
			}
			if len(sources) != 1 || !sources[0].Quarantined || sources[0].QuarantineStatus != statusCode {
				t.Fatalf("expected source to be locally quarantined with HTTP %d, got %#v", statusCode, sources)
			}
			if _, err := os.Stat(filepath.Join(directory, "quarantine.ndjson")); err != nil {
				t.Fatalf("quarantine was not persisted: %v", err)
			}
			if err := sender.Complete(); err != nil {
				t.Fatalf("complete quarantined batch: %v", err)
			}
		})
	}
}

func TestSendSplits413AndPreservesRecordIdentityAcrossRestart(t *testing.T) {
	var received []Batch
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		var batch Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		received = append(received, batch)

		if requestCount == 1 {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = writer.Write([]byte(`{"success":false,"message":"split required"}`))
			return
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"success":true,"data":{"success":true,"batch_id":"%s","status":"accepted","record_count":%d,"accepted_count":%d,"duplicate_count":0,"rejected_count":0,"replayed":false}}`,
			batch.BatchID,
			len(batch.Records),
			len(batch.Records),
		)
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	inputs := []InputRecord{
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"metric":1}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       "split-event-1",
			},
		},
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"metric":2}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       "split-event-2",
			},
		},
	}

	original, err := sender.buildPending("22222222-2222-4222-8222-222222222222", inputs)
	if err != nil {
		t.Fatalf("build original batch: %v", err)
	}
	originalBatchID := original.Batch.BatchID
	originalRecords := append([]Record(nil), original.Batch.Records...)
	if err := sender.savePending(*original); err != nil {
		t.Fatalf("persist original batch: %v", err)
	}

	sources, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("handle HTTP 413: %v", err)
	}
	if len(sources) != 0 {
		t.Fatalf("HTTP 413 split must not acknowledge sources: %#v", sources)
	}

	pending, err := sender.loadPending()
	if err != nil {
		t.Fatalf("load split queue: %v", err)
	}
	if pending.Batch.BatchID == originalBatchID || len(pending.Batch.Records) != 1 || len(pending.Following) != 1 {
		t.Fatal("split queue did not create two child batches with a new batch ID")
	}

	afterRestart, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("recreate sender after restart: %v", err)
	}
	afterRestart.client = server.Client()

	firstSources, err := afterRestart.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("send first split child: %v", err)
	}
	if len(firstSources) != 1 {
		t.Fatalf("expected first child acknowledgement, got %#v", firstSources)
	}
	if err := afterRestart.Complete(); err != nil {
		t.Fatalf("advance split queue: %v", err)
	}

	secondSources, err := afterRestart.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("send second split child: %v", err)
	}
	if len(secondSources) != 1 {
		t.Fatalf("expected second child acknowledgement, got %#v", secondSources)
	}
	if err := afterRestart.Complete(); err != nil {
		t.Fatalf("complete second split child: %v", err)
	}

	if len(received) != 3 {
		t.Fatalf("expected original 413 and two child requests, got %d", len(received))
	}
	if received[0].BatchID == received[1].BatchID || received[0].BatchID == received[2].BatchID || received[1].BatchID == received[2].BatchID {
		t.Fatal("split batches must each have new, distinct batch IDs")
	}

	for index, batch := range received[1:] {
		if len(batch.Records) != 1 {
			t.Fatalf("split child %d has %d records", index, len(batch.Records))
		}
		found := false
		for _, originalRecord := range originalRecords {
			if batch.Records[0].RecordID == originalRecord.RecordID &&
				batch.Records[0].Sequence == originalRecord.Sequence {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("split child %d changed record_id or sequence", index)
		}
	}
}

func TestBuildPendingRespectsOneMiBBatchLimit(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}

	applicationID := "11111111-1111-4111-8111-111111111111"
	payload := json.RawMessage(`{"value":"` + strings.Repeat("x", 3000) + `"}`)
	inputs := make([]InputRecord, MaximumBatchRecords)
	for index := range inputs {
		inputs[index] = InputRecord{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          payload,
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       fmt.Sprintf("large-event-%d", index),
			},
		}
	}

	pending, err := sender.buildPending("22222222-2222-4222-8222-222222222222", inputs)
	if err != nil {
		t.Fatalf("build size-bounded batch: %v", err)
	}
	encoded, err := json.Marshal(pending.Batch)
	if err != nil {
		t.Fatalf("encode size-bounded batch: %v", err)
	}
	if len(encoded) > MaximumBatchBytes {
		t.Fatalf("batch exceeds 1 MiB: %d", len(encoded))
	}
	if len(pending.Batch.Records) >= MaximumBatchRecords {
		t.Fatal("expected byte limit to stop the batch before the 500-record limit")
	}
}

func TestSendRetries429AndHonorsRetryAfter(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		var batch Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		if requestCount == 1 {
			writer.Header().Set("Retry-After", "1")
			writer.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"success":true,"data":{"success":true,"batch_id":"%s","status":"accepted","record_count":1,"accepted_count":1,"duplicate_count":0,"rejected_count":0,"replayed":false}}`,
			batch.BatchID,
		)
	}))
	defer server.Close()

	sender, err := NewSender(server.URL, t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	sources, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", []InputRecord{{
		Stream:        "application_metrics",
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{}`),
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "retry-429",
		},
	}})
	if err != nil {
		t.Fatalf("send after HTTP 429: %v", err)
	}
	if requestCount != 2 || len(sources) != 1 {
		t.Fatalf("expected one bounded retry and one acknowledgement, requests=%d sources=%d", requestCount, len(sources))
	}
}

func TestSendBounds503RetriesAndRetainsPendingBatch(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	_, err = sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", []InputRecord{{
		Stream:        "application_metrics",
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{}`),
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "retry-503",
		},
	}})
	var statusError *HTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected bounded HTTP 503 error, got %v", err)
	}
	if requestCount != 4 {
		t.Fatalf("expected four bounded attempts, got %d", requestCount)
	}
	if _, err := os.Stat(filepath.Join(directory, "pending-batch.json")); err != nil {
		t.Fatalf("pending batch was not retained after HTTP 503: %v", err)
	}
}

func TestSendQuarantinesSingleOversizedRecordWithoutRetry(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	data := json.RawMessage(`{"message":"` + strings.Repeat("x", MaximumRecordBytes) + `"}`)
	sources, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", []InputRecord{{
		Stream:        "application_logs",
		ApplicationID: &applicationID,
		Data:          data,
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "oversized-log",
		},
	}})
	if err != nil {
		t.Fatalf("quarantine oversized record: %v", err)
	}
	if requestCount != 0 {
		t.Fatalf("oversized record should not be sent to Central, got %d requests", requestCount)
	}
	if len(sources) != 1 || !sources[0].Quarantined || sources[0].QuarantineStatus != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized record was not quarantined with HTTP 413 disposition: %#v", sources)
	}
	if _, err := os.Stat(filepath.Join(directory, "quarantine.ndjson")); err != nil {
		t.Fatalf("oversized record quarantine was not durable: %v", err)
	}
}

func TestSplitDoesNotAcknowledgeSharedSpoolEventBeforeAllChildBatches(t *testing.T) {
	requestCount := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestCount++
		var batch Batch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			t.Fatalf("decode batch: %v", err)
		}
		if requestCount == 1 {
			writer.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(
			writer,
			`{"success":true,"data":{"success":true,"batch_id":"%s","status":"accepted","record_count":1,"accepted_count":1,"duplicate_count":0,"rejected_count":0,"replayed":false}}`,
			batch.BatchID,
		)
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	sharedSource := Source{
		Kind:          "application",
		ApplicationID: applicationID,
		EventID:       "one-spool-event",
	}
	inputs := []InputRecord{
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"health":true}`),
			Source:        sharedSource,
		},
		{
			Stream:        "database_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"connections":2}`),
			Source:        sharedSource,
		},
	}

	if _, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", inputs); err != nil {
		t.Fatalf("split original batch: %v", err)
	}
	firstAcknowledgement, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("send first split child: %v", err)
	}
	if len(firstAcknowledgement) != 0 {
		t.Fatalf("shared spool event was acknowledged before its final child: %#v", firstAcknowledgement)
	}

	pendingSources, hasPending, err := sender.PendingSources()
	if err != nil {
		t.Fatalf("inspect second split child: %v", err)
	}
	if !hasPending || len(pendingSources) != 1 ||
		pendingSources[0].EventID != sharedSource.EventID ||
		pendingSources[0].Stream != "database_metrics" {
		t.Fatalf("expected only the still-pending database stream to remain: %#v", pendingSources)
	}

	finalAcknowledgement, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", nil)
	if err != nil {
		t.Fatalf("send final split child: %v", err)
	}
	if len(finalAcknowledgement) != 1 || finalAcknowledgement[0].EventID != sharedSource.EventID {
		t.Fatalf("expected one final source acknowledgement, got %#v", finalAcknowledgement)
	}
	if err := sender.Complete(); err != nil {
		t.Fatalf("complete final split child: %v", err)
	}
}

func TestDiscardPendingQuarantinesEverySplitChildDurably(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	inputs := []InputRecord{
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"metric":1}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       "discard-event-1",
			},
		},
		{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{"metric":2}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       "discard-event-2",
			},
		},
	}

	if _, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", inputs); err != nil {
		t.Fatalf("split batch before discard: %v", err)
	}
	if err := sender.DiscardPending(); err != nil {
		t.Fatalf("quarantine pending split children: %v", err)
	}

	if _, hasPending, err := sender.PendingSources(); err != nil {
		t.Fatalf("inspect discarded pending batch: %v", err)
	} else if hasPending {
		t.Fatal("pending split queue remains after durable quarantine")
	}

	file, err := os.Open(filepath.Join(directory, "quarantine.ndjson"))
	if err != nil {
		t.Fatalf("open quarantine file: %v", err)
	}
	defer file.Close()

	var entries []QuarantineEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry QuarantineEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode quarantine entry: %v", err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read quarantine entries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected both split children in quarantine, got %d entries", len(entries))
	}

	eventIDs := map[string]bool{}
	for _, entry := range entries {
		for _, source := range entry.Pending.Sources {
			eventIDs[source.EventID] = true
		}
	}
	if !eventIDs["discard-event-1"] || !eventIDs["discard-event-2"] {
		t.Fatalf("quarantine did not preserve all source events: %#v", eventIDs)
	}
}

func TestBuildPendingNeverCutsOneSpoolEventAtTheRecordLimit(t *testing.T) {
	sender, err := NewSender("https://central.example", t.TempDir(), time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}

	applicationID := "11111111-1111-4111-8111-111111111111"
	inputs := make([]InputRecord, 0, MaximumBatchRecords+1)
	for index := 0; index < MaximumBatchRecords-1; index++ {
		inputs = append(inputs, InputRecord{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{}`),
			Source: Source{
				Kind:          "application",
				ApplicationID: applicationID,
				EventID:       fmt.Sprintf("single-event-%d", index),
			},
		})
	}
	sharedSource := Source{
		Kind:          "application",
		ApplicationID: applicationID,
		EventID:       "two-record-event",
	}
	inputs = append(inputs,
		InputRecord{
			Stream:        "application_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{}`),
			Source:        sharedSource,
		},
		InputRecord{
			Stream:        "database_metrics",
			ApplicationID: &applicationID,
			Data:          json.RawMessage(`{}`),
			Source:        sharedSource,
		},
	)

	pending, err := sender.buildPending("22222222-2222-4222-8222-222222222222", inputs)
	if err != nil {
		t.Fatalf("build source-atomic batch: %v", err)
	}
	if len(pending.Batch.Records) != MaximumBatchRecords-1 {
		t.Fatalf("expected the builder to stop before the two-record source event, got %d records", len(pending.Batch.Records))
	}
	for _, source := range pending.Sources {
		if source.EventID == sharedSource.EventID {
			t.Fatal("builder included only part of a source event")
		}
	}
}

func TestSendRetainsPendingBatchWhenCentralACKIsInvalid(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"success":true,
			"data":{
				"success":true,
				"batch_id":"33333333-3333-4333-8333-333333333333",
				"status":"accepted",
				"record_count":1,
				"accepted_count":1,
				"duplicate_count":0,
				"rejected_count":0,
				"replayed":false
			}
		}`))
	}))
	defer server.Close()

	directory := t.TempDir()
	sender, err := NewSender(server.URL, directory, time.Second)
	if err != nil {
		t.Fatalf("create sender: %v", err)
	}
	sender.client = server.Client()

	applicationID := "11111111-1111-4111-8111-111111111111"
	sources, err := sender.Send(context.Background(), "agent-1", "22222222-2222-4222-8222-222222222222", "credential", []InputRecord{{
		Stream:        "application_metrics",
		ApplicationID: &applicationID,
		Data:          json.RawMessage(`{}`),
		Source: Source{
			Kind:          "application",
			ApplicationID: applicationID,
			EventID:       "invalid-ack-event",
		},
	}})
	if err == nil {
		t.Fatal("expected mismatched Central batch ID to be rejected")
	}
	if len(sources) != 0 {
		t.Fatalf("invalid ACK must not acknowledge local sources: %#v", sources)
	}
	if _, err := os.Stat(filepath.Join(directory, "pending-batch.json")); err != nil {
		t.Fatalf("pending batch was removed after invalid ACK: %v", err)
	}
}
