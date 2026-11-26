package provision

import (
    "errors"
    "os"
    "path/filepath"
    "testing"
)

func TestInstallProvisionAssetsJournaledRollsBackEarlierAssetsOnFailure(t *testing.T)
{
    directory := t.TempDir()
    journalPath := filepath.Join(directory, "provisioning-journal.json")
    agentPath := filepath.Join(directory, "nadi-agent")
    helperPath := filepath.Join(directory, "nadi-provision")

    existingHelper := []byte("unexpected pre-existing helper")
    if err := os.WriteFile(helperPath, existingHelper, 0600); err != nil
    {
        t.Fatal(err)
    }

    store, journal, err := newProvisionJournal(journalPath)
    if err != nil
    {
        t.Fatalf("create provisioning journal: %v", err)
    }

    assets := []provisionAsset{
        {
            path: agentPath,
            content: []byte("verified signed Agent artifact"),
            mode: 0755,
            uid: os.Geteuid(),
            gid: os.Getegid(),
        },
        {
            path: helperPath,
            content: []byte("verified signed Agent artifact"),
            mode: 0755,
            uid: os.Geteuid(),
            gid: os.Getegid(),
        },
    }

    if err := installProvisionAssetsJournaled(assets, store, &journal); err == nil
    {
        t.Fatal("installation must fail when a conflicting helper already exists")
    }

    if err := store.Rollback(&journal, []string{directory}); err != nil
    {
        t.Fatalf("rollback partially installed assets: %v", err)
    }

    if _, err := os.Lstat(agentPath); !errors.Is(err, os.ErrNotExist)
    {
        t.Fatalf("earlier Agent asset must be removed by rollback, got: %v", err)
    }

    actualHelper, err := os.ReadFile(helperPath)
    if err != nil
    {
        t.Fatalf("read pre-existing helper after rollback: %v", err)
    }
    if string(actualHelper) != string(existingHelper)
    {
        t.Fatal("rollback must preserve the conflicting pre-existing helper byte-for-byte")
    }

    if journal.Phase != "rolled_back"
    {
        t.Fatalf("expected rolled_back journal phase, got %q", journal.Phase)
    }
    if len(journal.Actions) != 1 || journal.Actions[0].State != "rolled_back"
    {
        t.Fatalf("expected only the created Agent asset to be rolled back, got %#v", journal.Actions)
    }
}
