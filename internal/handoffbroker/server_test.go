package handoffbroker

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeRequestRejectsDuplicateKeys(t *testing.T) {
	payload := []byte(`{"protocol_version":1,"protocol_version":1,"operation":"publish_activation_state"}`)

	if _, err := decodeRequest(payload); err == nil {
		t.Fatal("expected duplicate JSON key to be rejected")
	}
}

func TestDecodeRequestRejectsUnknownFields(t *testing.T) {
	payload := []byte(`{"protocol_version":1,"operation":"publish_activation_state","application_id":"app","application_key":"key","unexpected":"value"}`)

	if _, err := decodeRequest(payload); err == nil {
		t.Fatal("expected unknown JSON field to be rejected")
	}
}

func TestDecodeRequestRejectsTrailingValues(t *testing.T) {
	payload := []byte(`{"protocol_version":1} {}`)

	if _, err := decodeRequest(payload); err == nil {
		t.Fatal("expected trailing JSON value to be rejected")
	}
}

func TestValidateActivationRequestAcceptsActiveGrantCapabilities(t *testing.T) {
	now := time.Now().UTC()
	request := Request{
		ProtocolVersion:   1,
		Operation:         "publish_activation_state",
		ApplicationID:     "00000000-0000-4000-8000-000000000001",
		ApplicationKey:    "stable-key",
		ActivationState:   "active",
		MonitoringEnabled: true,
		GrantAcknowledged: true,
		Capabilities:      []string{"application_metrics", "database_monitoring"},
		ObservedAt:        now.Format(time.RFC3339),
		ValidUntil:        now.Add(MaximumAssertionLifetime).Format(time.RFC3339),
	}

	if err := validateActivationRequest(request, now); err != nil {
		t.Fatalf("valid active assertion was rejected: %v", err)
	}
}

func TestValidateActivationRequestRejectsBridgeCapabilityNames(t *testing.T) {
	now := time.Now().UTC()
	request := Request{
		ProtocolVersion:   1,
		Operation:         "publish_activation_state",
		ApplicationID:     "00000000-0000-4000-8000-000000000001",
		ApplicationKey:    "stable-key",
		ActivationState:   "active",
		MonitoringEnabled: true,
		GrantAcknowledged: true,
		Capabilities:      []string{"health"},
		ObservedAt:        now.Format(time.RFC3339),
		ValidUntil:        now.Add(time.Minute).Format(time.RFC3339),
	}

	if err := validateActivationRequest(request, now); err == nil {
		t.Fatal("Bridge endpoint capability must not be accepted as a Central grant capability")
	}
}

func TestValidateActivationRequestRejectsActiveWithoutAcknowledgement(t *testing.T) {
	now := time.Now().UTC()
	request := Request{
		ProtocolVersion:   1,
		Operation:         "publish_activation_state",
		ApplicationID:     "00000000-0000-4000-8000-000000000001",
		ApplicationKey:    "stable-key",
		ActivationState:   "active",
		MonitoringEnabled: true,
		GrantAcknowledged: false,
		Capabilities:      []string{"application_metrics"},
		ObservedAt:        now.Format(time.RFC3339),
		ValidUntil:        now.Add(time.Minute).Format(time.RFC3339),
	}

	if err := validateActivationRequest(request, now); err == nil {
		t.Fatal("active assertion without accepted grant acknowledgement must be rejected")
	}
}

func TestValidateActivationRequestRejectsExpiredLease(t *testing.T) {
	now := time.Now().UTC()
	request := Request{
		ProtocolVersion: 1,
		Operation:       "publish_activation_state",
		ApplicationID:   "00000000-0000-4000-8000-000000000001",
		ApplicationKey:  "stable-key",
		ActivationState: "unknown",
		Capabilities:    []string{},
		ObservedAt:      now.Add(-10 * time.Minute).Format(time.RFC3339),
		ValidUntil:      now.Add(-5 * time.Minute).Format(time.RFC3339),
	}

	if err := validateActivationRequest(request, now); err == nil {
		t.Fatal("expired assertion must be rejected")
	}
}

func TestValidateConfigRejectsCredentialPathOutsideApplication(t *testing.T) {
	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications: []Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "stable-key",
				BasePath:            "/srv/www/app",
				RuntimeUID:          33,
				RuntimeGID:          33,
				CredentialFile:      "/etc/nadi-agent/credential",
				ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if err := validateConfig(config); err == nil {
		t.Fatal("credential path outside the application base path must be rejected")
	}
}

func TestValidateConfigRejectsDuplicateApplicationMappings(t *testing.T) {
	mapping := Mapping{
		ApplicationID:       "00000000-0000-4000-8000-000000000001",
		ApplicationKey:      "stable-key",
		BasePath:            "/srv/www/app",
		RuntimeUID:          33,
		RuntimeGID:          33,
		CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
		ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
	}

	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications:  []Mapping{mapping, mapping},
	}

	if err := validateConfig(config); err == nil {
		t.Fatal("duplicate application mapping must be rejected")
	}
}

func TestValidateConfigAcceptsPerApplicationRuntimeMapping(t *testing.T) {
	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications: []Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "stable-key",
				BasePath:            "/srv/www/app",
				RuntimeUID:          33,
				RuntimeGID:          33,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if err := validateConfig(config); err != nil {
		t.Fatalf("valid mapping was rejected: %v", err)
	}
}

func TestResponseNeverIncludesRawCredential(t *testing.T) {
	response := Response{
		ProtocolVersion: 1,
		Success:         false,
		ApplicationID:   "00000000-0000-4000-8000-000000000001",
		ErrorCode:       "credential_publish_failed",
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(string(encoded), "central-issued-secret") {
		t.Fatal("response unexpectedly contains credential material")
	}
}

func TestValidateMonotonicObservationRejectsOlderUpdate(t *testing.T) {
	previous := "2026-11-23T10:00:00Z"
	next := "2026-11-23T09:59:59Z"

	if err := validateMonotonicObservation(previous, next); err == nil {
		t.Fatal("older activation assertion must be rejected")
	}
}

func TestDecodeRequestRejectsCredentialFieldsOnActivationOperation(t *testing.T) {
	payload := []byte(`{"protocol_version":1,"operation":"publish_activation_state","application_id":"00000000-0000-4000-8000-000000000001","application_key":"stable-key","activation_state":"unknown","monitoring_enabled":false,"grant_acknowledged":false,"capabilities":[],"observed_at":"2026-11-23T10:00:00Z","valid_until":"2026-11-23T10:05:00Z","credential":"unexpected"}`)

	if _, err := decodeRequest(payload); err == nil {
		t.Fatal("credential field must not be accepted on activation operation")
	}
}

func TestDecodeRequestRequiresExplicitCapabilitiesArray(t *testing.T) {
	payload := []byte(`{"protocol_version":1,"operation":"publish_activation_state","application_id":"00000000-0000-4000-8000-000000000001","application_key":"stable-key","activation_state":"unknown","monitoring_enabled":false,"grant_acknowledged":false,"observed_at":"2026-11-23T10:00:00Z","valid_until":"2026-11-23T10:05:00Z"}`)

	if _, err := decodeRequest(payload); err == nil {
		t.Fatal("activation request must include the capabilities array")
	}
}

func TestHandleConnectionRejectsUnexpectedPeerUID(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "handoff.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	config := Config{
		SchemaVersion: 1,
		AgentUID:      uint32(os.Getuid() + 1),
		AgentGID:      uint32(os.Getgid() + 1),
		Applications: []Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "stable-key",
				BasePath:            "/srv/www/app",
				RuntimeUID:          33,
				RuntimeGID:          33,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}
	server := &Server{config: config}

	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		server.handleConnection(connection)
	}()

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	responseBytes, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}

	var response Response
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		t.Fatal(err)
	}

	if response.Success || response.ErrorCode != "peer_not_authorized" {
		t.Fatalf("unexpected response for untrusted peer: %#v", response)
	}

	<-done
}

func TestValidateConfigRejectsCredentialPathInsideWritableApplicationTree(t *testing.T) {
	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications: []Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "stable-key",
				BasePath:            "/srv/www/app",
				RuntimeUID:          33,
				RuntimeGID:          33,
				CredentialFile:      "/srv/www/app/storage/app/private/nadi/credential",
				ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if err := validateConfig(config); err == nil {
		t.Fatal("credential inside the application tree must be rejected")
	}
}

func TestValidateConfigAcceptsRootOwnedExternalCredentialDirectory(t *testing.T) {
	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications: []Mapping{
			{
				ApplicationID:       "00000000-0000-4000-8000-000000000001",
				ApplicationKey:      "stable-key",
				BasePath:            "/srv/www/app",
				RuntimeUID:          33,
				RuntimeGID:          33,
				CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
				ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
			},
		},
	}

	if err := validateConfig(config); err != nil {
		t.Fatalf("safe external credential path was rejected: %v", err)
	}
}

func TestValidateConfigRejectsDuplicateRuntimeUIDs(t *testing.T) {
	first := Mapping{
		ApplicationID:       "00000000-0000-4000-8000-000000000001",
		ApplicationKey:      "first-app",
		BasePath:            "/srv/www/first",
		RuntimeUID:          33,
		RuntimeGID:          33,
		CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000001/credential",
		ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000001.json",
	}
	second := Mapping{
		ApplicationID:       "00000000-0000-4000-8000-000000000002",
		ApplicationKey:      "second-app",
		BasePath:            "/srv/www/second",
		RuntimeUID:          33,
		RuntimeGID:          33,
		CredentialFile:      "/var/lib/nadi-bridge/00000000-0000-4000-8000-000000000002/credential",
		ActivationStateFile: "/run/nadi-agent/bridge-state/00000000-0000-4000-8000-000000000002.json",
	}

	config := Config{
		SchemaVersion: 1,
		AgentUID:      1001,
		AgentGID:      1001,
		Applications:  []Mapping{first, second},
	}

	if err := validateConfig(config); err == nil {
		t.Fatal("duplicate application runtime UID must be rejected")
	}
}
