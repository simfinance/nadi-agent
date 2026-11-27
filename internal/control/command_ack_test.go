package control

import (
    "context"
    "fmt"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestAcknowledgeCommandSendsExpectedRequest(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
        if request.Method != http.MethodPost {
            t.Errorf("expected POST, got %s", request.Method)
        }

        if request.URL.Path != "/api/v1/nadi/agent/commands/command-123/ack" {
            t.Errorf("unexpected command acknowledgement path: %s", request.URL.Path)
        }

        if request.Header.Get("Authorization") != "Bearer test-token" {
            t.Error("missing bearer authorization")
        }

        writer.Header().Set("Content-Type", "application/json")
        fmt.Fprint(writer, "{\"success\":true,\"acknowledged\":true,\"command_id\":\"command-123\"}")
    }))
    defer server.Close()

    client := NewClient(server.URL, "test-token", 2*time.Second)
    defer client.HTTP.CloseIdleConnections()

    if err := client.AcknowledgeCommand(context.Background(), "command-123"); err != nil {
        t.Fatalf("expected command receipt acknowledgement success, got: %v", err)
    }
}

func TestAcknowledgeCommandRejectsCentralError(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
        http.Error(writer, "{\"success\":false,\"message\":\"not delivered\"}", http.StatusConflict)
    }))
    defer server.Close()

    client := NewClient(server.URL, "test-token", 2*time.Second)
    defer client.HTTP.CloseIdleConnections()

    if err := client.AcknowledgeCommand(context.Background(), "command-123"); err == nil {
        t.Fatal("expected Central HTTP 409 to be rejected")
    }
}

func TestAcknowledgeCommandRejectsMissingToken(t *testing.T) {
    client := NewClient("https://central.example.test", "", time.Second)

    if err := client.AcknowledgeCommand(context.Background(), "command-123"); err == nil {
        t.Fatal("expected missing Agent credential error")
    }
}
