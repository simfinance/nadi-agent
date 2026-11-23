package handoff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	maximumRequestBytes  = 16 * 1024
	maximumResponseBytes = 4 * 1024
)

type Client struct {
	socketPath string
	timeout    time.Duration
}

type ActivationStateRequest struct {
	ProtocolVersion   int      `json:"protocol_version"`
	Operation         string   `json:"operation"`
	ApplicationID     string   `json:"application_id"`
	ApplicationKey    string   `json:"application_key"`
	ActivationState   string   `json:"activation_state"`
	MonitoringEnabled bool     `json:"monitoring_enabled"`
	GrantAcknowledged bool     `json:"grant_acknowledged"`
	Capabilities      []string `json:"capabilities"`
	ObservedAt        string   `json:"observed_at"`
	ValidUntil        string   `json:"valid_until"`
}

type CredentialRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Operation       string `json:"operation"`
	ApplicationID   string `json:"application_id"`
	ApplicationKey  string `json:"application_key"`
	Credential      string `json:"credential"`
}

type Response struct {
	ProtocolVersion   int    `json:"protocol_version"`
	Success           bool   `json:"success"`
	ApplicationID     string `json:"application_id"`
	CredentialVersion int    `json:"credential_version,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
}

func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !strings.HasPrefix(socketPath, "/") {
		return nil, errors.New("handoff socket path must be absolute")
	}

	if timeout <= 0 {
		return nil, errors.New("handoff timeout must be positive")
	}

	return &Client{
		socketPath: socketPath,
		timeout:    timeout,
	}, nil
}

func (c *Client) PublishActivationState(request ActivationStateRequest) error {
	request.ProtocolVersion = 1
	request.Operation = "publish_activation_state"

	if request.ApplicationID == "" || request.ApplicationKey == "" {
		return errors.New("application identity is required")
	}

	if request.ActivationState != "pending_approval" &&
		request.ActivationState != "pending_activation" &&
		request.ActivationState != "active" &&
		request.ActivationState != "suspended" &&
		request.ActivationState != "revoked" &&
		request.ActivationState != "unknown" {
		return errors.New("activation state is invalid")
	}

	return c.exchange(request, request.ApplicationID)
}

func (c *Client) PublishApplicationCredential(request CredentialRequest) error {
	request.ProtocolVersion = 1
	request.Operation = "publish_application_credential"

	if request.ApplicationID == "" || request.ApplicationKey == "" || request.Credential == "" {
		return errors.New("application identity and credential are required")
	}

	return c.exchange(request, request.ApplicationID)
}

func (c *Client) exchange(request any, expectedApplicationID string) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode handoff request: %w", err)
	}

	if len(payload) == 0 || len(payload) > maximumRequestBytes {
		return errors.New("handoff request exceeds the allowed size")
	}

	connection, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return fmt.Errorf("connect to local handoff broker: %w", err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return fmt.Errorf("set handoff deadline: %w", err)
	}

	if _, err := connection.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("write handoff request: %w", err)
	}

	responseBytes, err := io.ReadAll(io.LimitReader(connection, maximumResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read handoff response: %w", err)
	}

	if len(responseBytes) == 0 || len(responseBytes) > maximumResponseBytes {
		return errors.New("handoff response is empty or exceeds the allowed size")
	}

	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()

	var response Response
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("decode handoff response: %w", err)
	}

	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("handoff response contains trailing JSON")
	}

	if response.ProtocolVersion != 1 || response.ApplicationID != expectedApplicationID {
		return errors.New("handoff response identity or protocol version mismatch")
	}

	if !response.Success {
		if response.ErrorCode == "" {
			return errors.New("handoff broker rejected the request")
		}

		return fmt.Errorf("handoff broker rejected the request: %s", response.ErrorCode)
	}

	return nil
}
