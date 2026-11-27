package appspool

import (
	"errors"
	"sync"
	"testing"
	"time"

	"nadi-agent/internal/appmonitor"
)

func TestApplicationSpoolIsolatesApplications(t *testing.T) {
	store, err := Open(t.TempDir(), DefaultMaxBytes, DefaultMaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := appmonitor.Snapshot{Timestamp: time.Now().UTC()}
	if _, err := store.Append("server-1", "agent-1", "app-1", snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append("server-1", "agent-1", "app-2", snapshot); err != nil {
		t.Fatal(err)
	}

	appOne, err := store.ReadBatch("app-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	appTwo, err := store.ReadBatch("app-2", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(appOne) != 1 || appOne[0].ApplicationID != "app-1" {
		t.Fatalf("unexpected app-1 records: %#v", appOne)
	}
	if len(appTwo) != 1 || appTwo[0].ApplicationID != "app-2" {
		t.Fatalf("unexpected app-2 records: %#v", appTwo)
	}

	if err := store.Clear("app-1"); err != nil {
		t.Fatal(err)
	}
	appOne, err = store.ReadBatch("app-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	appTwo, err = store.ReadBatch("app-2", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(appOne) != 0 || len(appTwo) != 1 {
		t.Fatal("clearing one application spool affected another application")
	}
}

func TestApplicationSpoolAcknowledgesOnlyMatchingApplicationEvents(t *testing.T) {
	store, err := Open(t.TempDir(), DefaultMaxBytes, DefaultMaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := appmonitor.Snapshot{Timestamp: time.Now().UTC()}
	first, err := store.Append("server-1", "agent-1", "app-1", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Append("server-1", "agent-1", "app-1", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append("server-1", "agent-1", "app-2", snapshot); err != nil {
		t.Fatal(err)
	}

	if err := store.Acknowledge("app-1", []string{first.EventID}); err != nil {
		t.Fatal(err)
	}
	appOne, err := store.ReadBatch("app-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	appTwo, err := store.ReadBatch("app-2", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(appOne) != 1 || appOne[0].EventID != second.EventID {
		t.Fatalf("unexpected retained app-1 records: %#v", appOne)
	}
	if len(appTwo) != 1 {
		t.Fatal("acknowledging app-1 changed app-2 spool")
	}
}


func TestConcurrentAppendCannotExceedApplicationCapacity(t *testing.T) {
	store, err := Open(t.TempDir(), 1024*1024, 1)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 16
	var wait sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	full := 0
	unexpected := make([]error, 0)

	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()

			_, appendErr := store.Append(
				"server-1",
				"agent-1",
				"app-1",
				appmonitor.Snapshot{Timestamp: time.Now().UTC()},
			)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case appendErr == nil:
				successes++
			case errors.Is(appendErr, ErrFull):
				full++
			default:
				unexpected = append(unexpected, appendErr)
			}
		}()
	}

	wait.Wait()

	if len(unexpected) > 0 {
		t.Fatalf("unexpected append errors: %v", unexpected)
	}
	if successes != 1 || full != workers-1 {
		t.Fatalf("application capacity was not enforced under concurrency: successes=%d full=%d", successes, full)
	}

	records, err := store.ReadBatch("app-1", workers)
	if err != nil {
		t.Fatalf("read application spool: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly one persisted application record, got %d", len(records))
	}
}
