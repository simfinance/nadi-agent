package logdedupe

import (
	"fmt"
	"testing"
)

func TestStorePersistsFingerprintsAcrossRestart(t *testing.T) {
	directory := t.TempDir()

	first, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Commit("application:app-1", []string{"fingerprint-a", "fingerprint-b"}); err != nil {
		t.Fatal(err)
	}

	second, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	unseen, err := second.Unseen("application:app-1", []string{"fingerprint-a", "fingerprint-c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unseen) != 1 || unseen[0] != "fingerprint-c" {
		t.Fatalf("unexpected unseen fingerprints: %#v", unseen)
	}
}

func TestStoreIsolatesScopes(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit("application:app-a", []string{"shared-fingerprint"}); err != nil {
		t.Fatal(err)
	}

	unseen, err := store.Unseen("application:app-b", []string{"shared-fingerprint"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unseen) != 1 {
		t.Fatalf("expected fingerprint to be unseen in another scope, got %#v", unseen)
	}
}

func TestStorePreservesDuplicateOccurrencesInOneCollection(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	unseen, err := store.Unseen("server", []string{"same", "same"})
	if err != nil {
		t.Fatal(err)
	}
	if len(unseen) != 2 {
		t.Fatalf("expected both same-cycle occurrences, got %#v", unseen)
	}
}

func TestStoreBoundsPersistedFingerprints(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	values := make([]string, MaximumFingerprints+2)
	for index := range values {
		values[index] = fmt.Sprintf("fingerprint-%d", index)
	}
	if err := store.Commit("server", values); err != nil {
		t.Fatal(err)
	}

	persisted, err := store.loadOrdered("server")
	if err != nil {
		t.Fatal(err)
	}
	if len(persisted) != MaximumFingerprints {
		t.Fatalf("expected %d fingerprints, got %d", MaximumFingerprints, len(persisted))
	}
	if persisted[0] != "fingerprint-2" {
		t.Fatalf("oldest fingerprint was not evicted: %q", persisted[0])
	}
}
