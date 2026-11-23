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
	defaultTimeout       = 3 * time.Second
)

type applicationCredentialRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Operation       string `json:"operation"`
	ApplicationID   string `json:"application_id"`
	ApplicationKey  string `json:"application_key"`
	Credential      string `json:"credential"`
}

type brokerResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func PublishApplicationCredential(
	socketPath string,
	applicationID string,
	applicationKey string,
	credential string,
) error {
	if !strings.HasPrefix(socketPath, "/") {
		return errors.New("credential handoff socket path must be absolute")
	}

	if strings.TrimSpace(applicationID) == "" ||
		strings.TrimSpace(applicationKey) == "" ||
		strings.TrimSpace(credential) == "" {
		return errors.New("application identity and credential are required")
	}

	request := applicationCredentialRequest{
		ProtocolVersion: 1,
		Operation:       "publish_application_credential",
		ApplicationID:   applicationID,
		ApplicationKey:  applicationKey,
		Credential:      credential,
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode application credential handoff request: %w", err)
	}

	if len(payload) > maximumRequestBytes {
		return errors.New("application credential handoff request exceeds the size limit")
	}

	connection, err := net.DialTimeout("unix", socketPath, defaultTimeout)
	if err != nil {
		return fmt.Errorf("connect to credential handoff broker: %w", err)
	}
	defer connection.Close()

	if err := connection.SetDeadline(time.Now().Add(defaultTimeout)); err != nil {
		return fmt.Errorf("set credential handoff deadline: %w", err)
	}

	if _, err := connection.Write(append(payload, '\n')); err != nil {
		return fmt.Errorf("send application credential handoff request: %w", err)
	}

	responseBytes, err := io.ReadAll(io.LimitReader(connection, maximumResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read credential handoff broker response: %w", err)
	}

	if len(responseBytes) == 0 || len(responseBytes) > maximumResponseBytes {
		return errors.New("credential handoff broker response is empty or exceeds the size limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()

	var response brokerResponse
	if err := decoder.Decode(&response); err != nil {
		return fmt.Errorf("decode credential handoff broker response: %w", err)
	}

	if err := ensureResponseEOF(decoder); err != nil {
		return err
	}

	if !response.Success {
		if response.Error == "" {
			return errors.New("credential handoff broker rejected the request")
		}

		return fmt.Errorf("credential handoff broker rejected the request: %s", response.Error)
	}

	if response.Error != "" {
		return errors.New("credential handoff broker returned an inconsistent response")
	}

	return nil
}

func ensureResponseEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("credential handoff broker returned multiple JSON values")
		}

		return fmt.Errorf("validate credential handoff broker response: %w", err)
	}

	return nil
}
