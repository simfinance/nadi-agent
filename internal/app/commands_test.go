package app

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "net/http"
    "net/http/httptest"
    "os"
    "path/filepath"
    "testing"
    "time"

    "nadi-agent/internal/config"
    "nadi-agent/internal/control"
    "nadi-agent/internal/state"
)

func TestAcceptCommandsPersistsBeforeAcknowledgementAndDeduplicates(t *testing.T) {
    stateDirectory := t.TempDir()
    acknowledgementRequests := 0

    server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
        acknowledgementRequests++

        if request.Method != http.MethodPost {
            t.Errorf("expected POST, got %s", request.Method)
        }

        if request.URL.Path != "/api/v1/nadi/agent/commands/command-123/ack" {
            t.Errorf("unexpected acknowledgement path: %s", request.URL.Path)
        }

        content, err := os.ReadFile(filepath.Join(stateDirectory, "state.json"))
        if err != nil {
            t.Fatalf("read persisted state before acknowledgement: %v", err)
        }

        var persisted state.State
        if err := json.Unmarshal(content, &persisted); err != nil {
            t.Fatalf("decode persisted state before acknowledgement: %v", err)
        }

        if len(persisted.ReceivedCommands) != 1 || persisted.ReceivedCommands[0].Acknowledged {
            t.Fatal("command was not durably stored before Central acknowledgement")
        }

        writer.Header().Set("Content-Type", "application/json")
        fmt.Fprint(
            writer,
            "{\"success\":true,\"acknowledged\":true,\"command_id\":\"command-123\"}",
        )
    }))
    defer server.Close()

    store, err := state.Open(stateDirectory)
    if err != nil {
        t.Fatalf("open Agent state: %v", err)
    }
    defer store.Close()

    if err := store.Save(state.State{
        AgentInstanceID: "instance-123",
    }); err != nil {
        t.Fatalf("save initial Agent state: %v", err)
    }

    application := &App{
        config: config.Config{
            CentralURL: server.URL,
        },
        logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
        controlHTTP: control.NewClient(
            server.URL,
            "test-agent-token",
            2*time.Second,
        ),
    }
    defer application.controlHTTP.HTTP.CloseIdleConnections()

    command := control.Command{
        CommandID:     "command-123",
        ApplicationID: "application-123",
        CommandType:   "collect_status",
        Payload:       json.RawMessage("{\"scope\":\"health\"}"),
        IssuedAt:      time.Now().UTC().Format(time.RFC3339Nano),
        ExpiresAt:     time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
    }

    if err := application.acceptCommands(context.Background(), store, []control.Command{command}); err != nil {
        t.Fatalf("accept command: %v", err)
    }

    persisted, err := store.Load()
    if err != nil {
        t.Fatalf("load acknowledged Agent state: %v", err)
    }

    if len(persisted.ReceivedCommands) != 1 {
        t.Fatalf("expected one durable command, got %d", len(persisted.ReceivedCommands))
    }

    if !persisted.ReceivedCommands[0].Acknowledged {
        t.Fatal("command receipt acknowledgement was not persisted")
    }

    if err := application.acceptCommands(context.Background(), store, []control.Command{command}); err != nil {
        t.Fatalf("accept duplicate command: %v", err)
    }

    if acknowledgementRequests != 1 {
        t.Fatalf("expected one acknowledgement request for duplicate delivery, got %d", acknowledgementRequests)
    }
}

func TestValidateReceivedCommandRejectsExpiredAndInvalidPayload(t *testing.T) {
    now := time.Now().UTC()

    expired := control.Command{
        CommandID:     "command-expired",
        ApplicationID: "application-123",
        CommandType:   "collect_status",
        Payload:       json.RawMessage("{}"),
        IssuedAt:      now.Add(-time.Hour).Format(time.RFC3339Nano),
        ExpiresAt:     now.Add(-time.Minute).Format(time.RFC3339Nano),
    }

    if _, err := validateReceivedCommand(expired, now); err == nil {
        t.Fatal("expected expired command to be rejected")
    }

    invalidPayload := control.Command{
        CommandID:     "command-invalid",
        ApplicationID: "application-123",
        CommandType:   "collect_status",
        Payload:       json.RawMessage("{invalid"),
        IssuedAt:      now.Format(time.RFC3339Nano),
    }

    if _, err := validateReceivedCommand(invalidPayload, now); err == nil {
        t.Fatal("expected invalid command payload to be rejected")
    }
}
