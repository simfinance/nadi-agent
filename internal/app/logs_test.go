package app

import (
	"encoding/json"
	"testing"

	"nadi-agent/internal/logdedupe"
)

func TestFilterApplicationLogSummaryDeduplicatesPerApplication(t *testing.T) {
	store, err := logdedupe.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	data := json.RawMessage(`{
		"source":"laravel_application",
		"entries":[
			{"timestamp":"2026-11-23T08:00:00Z","level":"ERROR","exception_type":"RuntimeException","fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			{"timestamp":"2026-11-23T08:00:01Z","level":"ERROR","exception_type":"LogicException","fingerprint":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
		]
	}`)

	filtered, fingerprints, err := filterApplicationLogSummary(store, "app-a", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprints) != 2 {
		t.Fatalf("expected two new fingerprints, got %#v", fingerprints)
	}

	var firstPayload applicationLogSummaryPayload
	if err := json.Unmarshal(filtered, &firstPayload); err != nil {
		t.Fatal(err)
	}
	if len(firstPayload.Entries) != 2 {
		t.Fatalf("expected both new log entries to be retained, got %d", len(firstPayload.Entries))
	}

	if err := store.Commit("application:app-a", fingerprints); err != nil {
		t.Fatal(err)
	}

	repeated, unseen, err := filterApplicationLogSummary(store, "app-a", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(unseen) != 0 {
		t.Fatalf("expected no unseen fingerprints, got %#v", unseen)
	}

	var payload applicationLogSummaryPayload
	if err := json.Unmarshal(repeated, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Entries) != 0 {
		t.Fatalf("expected repeated entries to be filtered, got %d", len(payload.Entries))
	}

	otherApplication, otherUnseen, err := filterApplicationLogSummary(store, "app-b", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherUnseen) != 2 {
		t.Fatalf("expected application B to have independent fingerprints, got %#v", otherUnseen)
	}
	if len(otherApplication) == 0 {
		t.Fatal("expected filtered application B payload")
	}
}
