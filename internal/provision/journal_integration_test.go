package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProvisionJournalRetainsFixedServiceAccount(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "account", "nadi-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRetained(&journal, index); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(&journal); err != nil {
		t.Fatalf("commit with retained account: %v", err)
	}
	if journal.Actions[index].State != "retained" {
		t.Fatalf("expected service account to be retained, got %q", journal.Actions[index].State)
	}
}

func TestProvisionJournalParentRejectsGroupWritableDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatal(err)
	}

	_, _, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err == nil {
		t.Fatal("group-writable journal parent must be rejected")
	}
}

func TestProvisionJournalRollbackDoesNotDeleteRetainedAccount(t *testing.T) {
	directory := t.TempDir()
	store, journal, err := newProvisionJournal(filepath.Join(directory, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}

	index, err := store.AddIntent(&journal, "account", "nadi-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRetained(&journal, index); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(&journal, []string{directory}); err != nil {
		t.Fatalf("rollback with retained service account: %v", err)
	}
	if journal.Actions[index].State != "retained" {
		t.Fatalf("retained account state changed: %q", journal.Actions[index].State)
	}
}
