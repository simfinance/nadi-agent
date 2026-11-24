package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"nadi-agent/internal/handoffbroker"
)

const (
	maximumEnrollmentSummaryBytes = 16 * 1024
	brokerMappingPath             = "/etc/nadi/bridge-mappings.json"
	brokerDropInPath              = "/etc/systemd/system/nadi-handoff-broker.service.d/bridge-credentials.conf"
)

type enrollmentSummary struct {
	ProtocolVersion  int                            `json:"protocol_version"`
	EnrollmentStatus string                         `json:"enrollment_status"`
	AgentInstanceID  string                         `json:"agent_instance_id"`
	AgentID          string                         `json:"agent_id"`
	ServerID         string                         `json:"server_id"`
	Applications     []enrollmentSummaryApplication `json:"applications"`
}

type enrollmentSummaryApplication struct {
	ApplicationID   string `json:"application_id"`
	ApplicationKey  string `json:"application_key"`
	ApplicationName string `json:"application_name"`
	Environment     string `json:"environment"`
	RegistrationID  string `json:"registration_id"`
}

// BuildBrokerArtifacts reconciles the non-secret Agent enrollment summary with
// the prevalidated local application inventory. It does not read Agent state.
func BuildBrokerArtifacts(
	agentUID uint32,
	agentGID uint32,
	request ProvisionRequest,
	summaryJSON []byte,
) (handoffbroker.Config, []byte, string, error) {
	if agentUID == 0 || agentGID == 0 {
		return handoffbroker.Config{}, nil, "", errors.New("nadi-agent UID and GID must be non-root")
	}

	if len(summaryJSON) == 0 || len(summaryJSON) > maximumEnrollmentSummaryBytes {
		return handoffbroker.Config{}, nil, "", errors.New("enrollment summary is empty or exceeds the allowed size")
	}

	if err := rejectDuplicateJSONKeys(summaryJSON); err != nil {
		return handoffbroker.Config{}, nil, "", fmt.Errorf("enrollment summary JSON is ambiguous: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(summaryJSON))
	decoder.DisallowUnknownFields()

	var summary enrollmentSummary
	if err := decoder.Decode(&summary); err != nil {
		return handoffbroker.Config{}, nil, "", fmt.Errorf("decode enrollment summary: %w", err)
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return handoffbroker.Config{}, nil, "", fmt.Errorf("enrollment summary has trailing data: %w", err)
	}

	if summary.ProtocolVersion != 1 ||
		summary.EnrollmentStatus != "registered" ||
		strings.TrimSpace(summary.AgentInstanceID) == "" ||
		strings.TrimSpace(summary.AgentID) == "" ||
		strings.TrimSpace(summary.ServerID) == "" {
		return handoffbroker.Config{}, nil, "", errors.New("enrollment summary identity or status is invalid")
	}

	if len(summary.Applications) != len(request.Applications) ||
		len(summary.Applications) < 1 ||
		len(summary.Applications) > 20 {
		return handoffbroker.Config{}, nil, "", errors.New("enrollment summary application count does not match the local inventory")
	}

	localByKey := make(map[string]ProvisionApplication, len(request.Applications))
	for _, application := range request.Applications {
		if _, exists := localByKey[application.ApplicationKey]; exists {
			return handoffbroker.Config{}, nil, "", errors.New("local inventory contains duplicate application keys")
		}

		localByKey[application.ApplicationKey] = application
	}

	config := handoffbroker.Config{
		SchemaVersion: 1,
		AgentUID:      agentUID,
		AgentGID:      agentGID,
		Applications:  make([]handoffbroker.Mapping, 0, len(summary.Applications)),
	}

	seenApplicationIDs := make(map[string]struct{}, len(summary.Applications))
	seenApplicationKeys := make(map[string]struct{}, len(summary.Applications))

	for _, application := range summary.Applications {
		if application.ApplicationID == "" || application.ApplicationKey == "" {
			return handoffbroker.Config{}, nil, "", errors.New("enrollment summary contains an incomplete application identity")
		}

		if _, exists := seenApplicationIDs[application.ApplicationID]; exists {
			return handoffbroker.Config{}, nil, "", errors.New("enrollment summary contains duplicate application IDs")
		}

		if _, exists := seenApplicationKeys[application.ApplicationKey]; exists {
			return handoffbroker.Config{}, nil, "", errors.New("enrollment summary contains duplicate application keys")
		}

		local, exists := localByKey[application.ApplicationKey]
		if !exists {
			return handoffbroker.Config{}, nil, "", errors.New("Central enrollment summary contains an unknown application key")
		}

		seenApplicationIDs[application.ApplicationID] = struct{}{}
		seenApplicationKeys[application.ApplicationKey] = struct{}{}

		config.Applications = append(config.Applications, handoffbroker.Mapping{
			ApplicationID:       application.ApplicationID,
			ApplicationKey:      application.ApplicationKey,
			BasePath:            local.BasePath,
			RuntimeUID:          local.RuntimeUID,
			RuntimeGID:          local.RuntimeGID,
			CredentialFile:      "/var/lib/nadi-bridge/" + application.ApplicationID + "/credential",
			ActivationStateFile: "/run/nadi/bridge-state/" + application.ApplicationID + ".json",
		})
	}

	if len(seenApplicationKeys) != len(localByKey) {
		return handoffbroker.Config{}, nil, "", errors.New("enrollment summary does not reconcile every local application")
	}

	sort.Slice(config.Applications, func(left int, right int) bool {
		return config.Applications[left].ApplicationID < config.Applications[right].ApplicationID
	})

	if _, err := handoffbroker.NewServer(
		"/run/nadi/credential-handoff.sock",
		config,
	); err != nil {
		return handoffbroker.Config{}, nil, "", fmt.Errorf("validate reconciled broker mapping: %w", err)
	}

	mappingJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return handoffbroker.Config{}, nil, "", fmt.Errorf("encode broker mapping: %w", err)
	}

	mappingJSON = append(mappingJSON, '\n')

	dropIn, err := BuildBrokerDropIn(config)
	if err != nil {
		return handoffbroker.Config{}, nil, "", err
	}

	return config, mappingJSON, dropIn, nil
}

// BuildBrokerDropIn grants the broker write access only to the exact
// per-application credential directories represented by a validated mapping.
func BuildBrokerDropIn(config handoffbroker.Config) (string, error) {
	if _, err := handoffbroker.NewServer(
		"/run/nadi/credential-handoff.sock",
		config,
	); err != nil {
		return "", fmt.Errorf("invalid broker mapping for systemd drop-in: %w", err)
	}

	paths := make([]string, 0, len(config.Applications))
	for _, application := range config.Applications {
		paths = append(paths, "/var/lib/nadi-bridge/"+application.ApplicationID)
	}

	sort.Strings(paths)

	var builder strings.Builder
	builder.WriteString("[Service]\n")

	for _, path := range paths {
		builder.WriteString("ReadWritePaths=")
		builder.WriteString(path)
		builder.WriteByte('\n')
	}

	return builder.String(), nil
}

// BrokerArtifactPaths returns the fixed destinations owned by the helper.
func BrokerArtifactPaths() (string, string) {
	return brokerMappingPath, brokerDropInPath
}

// ValidateEnrollmentSummaryReader is kept small for callers that need to
// reject oversized helper output before buffering it.
func ValidateEnrollmentSummaryReader(reader io.Reader) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maximumEnrollmentSummaryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read enrollment summary: %w", err)
	}

	if len(content) == 0 || len(content) > maximumEnrollmentSummaryBytes {
		return nil, errors.New("enrollment summary is empty or exceeds the allowed size")
	}

	return content, nil
}
