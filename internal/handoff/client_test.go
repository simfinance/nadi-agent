package handoff

import (
    "bufio"
    "encoding/json"
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

func TestPublishActivationStateUsesVersionedUnixSocketProtocol(t *testing.T) {
    socketPath := filepath.Join(t.TempDir(), "handoff.sock")
    listener, err := net.Listen("unix", socketPath)
    if err != nil {
        t.Fatal(err)
    }
    defer listener.Close()

    received := make(chan ActivationStateRequest, 1)
    go func() {
        connection, acceptErr := listener.Accept()
        if acceptErr != nil {
            return
        }
        defer connection.Close()

        var request ActivationStateRequest
        if decodeErr := json.NewDecoder(bufio.NewReader(connection)).Decode(&request); decodeErr != nil {
            return
        }
        received <- request

        _, _ = connection.Write([]byte(`{"protocol_version":1,"success":true,"application_id":"app-1"}` + "\n"))
    }()

    client, err := NewClient(socketPath, time.Second)
    if err != nil {
        t.Fatal(err)
    }

    now := time.Now().UTC()
    err = client.PublishActivationState(ActivationStateRequest{
        ApplicationID: "app-1",
        ApplicationKey: "stable-key",
        ActivationState: "active",
        MonitoringEnabled: true,
        GrantAcknowledged: true,
        Capabilities: []string{"application_metrics", "database_monitoring"},
        ObservedAt: now.Format(time.RFC3339),
        ValidUntil: now.Add(5 * time.Minute).Format(time.RFC3339),
    })
    if err != nil {
        t.Fatal(err)
    }

    request := <-received
    if request.ProtocolVersion != 1 || request.Operation != "publish_activation_state" {
        t.Fatalf("unexpected request protocol: %#v", request)
    }
    if len(request.Capabilities) != 2 || request.Capabilities[0] != "application_metrics" {
        t.Fatalf("Central capabilities were not preserved: %#v", request.Capabilities)
    }
}

func TestPublishApplicationCredentialDoesNotExposeCredentialInErrors(t *testing.T) {
    socketPath := filepath.Join(t.TempDir(), "missing.sock")
    client, err := NewClient(socketPath, 100*time.Millisecond)
    if err != nil {
        t.Fatal(err)
    }

    secret := "central-issued-secret-value"
    err = client.PublishApplicationCredential(CredentialRequest{
        ApplicationID: "app-1",
        ApplicationKey: "stable-key",
        Credential: secret,
    })
    if err == nil {
        t.Fatal("expected missing broker socket to fail")
    }
    if strings.Contains(err.Error(), secret) {
        t.Fatal("credential leaked into the error")
    }
}

func TestNewClientRequiresAbsoluteSocketPath(t *testing.T) {
    if _, err := NewClient("relative.sock", time.Second); err == nil {
        t.Fatal("expected relative socket path to be rejected")
    }
}

func TestHandoffSocketPathCanBeResolved(t *testing.T) {
    path := filepath.Join(t.TempDir(), "handoff.sock")
    if err := os.WriteFile(path, []byte("not a socket"), 0600); err != nil {
        t.Fatal(err)
    }

    if _, err := NewClient(path, time.Second); err != nil {
        t.Fatal(err)
    }
}
