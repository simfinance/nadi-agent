package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

const (
	provisionInventoryPath         = "/etc/nadi/provisioning-inventory.json"
	provisionCompletePath          = "/etc/nadi/provisioning-complete.json"
	provisionAttemptPath           = "/etc/nadi/provisioning-enrollment-attempt.json"
	maximumEnrollmentManifestBytes = 32 * 1024
)

type ProvisionOperationRequest struct {
	ProtocolVersion int                      `json:"protocol_version"`
	Operation       string                   `json:"operation"`
	Release         *ProvisionReleaseRequest `json:"release,omitempty"`
	Applications    []ProvisionApplication   `json:"applications,omitempty"`
	Enrollment      *ProvisionEnrollment     `json:"enrollment,omitempty"`
}

type provisionInventory struct {
	ProtocolVersion int                    `json:"protocol_version"`
	AgentVersion    string                 `json:"agent_version"`
	Applications    []ProvisionApplication `json:"applications"`
}

type provisionCompletion struct {
	ProtocolVersion  int    `json:"protocol_version"`
	AgentVersion     string `json:"agent_version"`
	ApplicationCount int    `json:"application_count"`
	EnrollmentStatus string `json:"enrollment_status"`
}

type provisionEnrollmentAttempt struct {
	ProtocolVersion  int    `json:"protocol_version"`
	ManifestSHA256   string `json:"manifest_sha256"`
	ApplicationCount int    `json:"application_count"`
}

func DecodeProvisionOperationRequest(reader io.Reader) (ProvisionOperationRequest, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maximumProvisionRequestBytes+1))
	if err != nil {
		return ProvisionOperationRequest{}, fmt.Errorf("read provisioning request: %w", err)
	}
	if len(content) == 0 || len(content) > maximumProvisionRequestBytes {
		return ProvisionOperationRequest{}, errors.New("provisioning request is empty or exceeds the size limit")
	}
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return ProvisionOperationRequest{}, fmt.Errorf("provisioning request JSON is ambiguous: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var request ProvisionOperationRequest
	if err := decoder.Decode(&request); err != nil {
		return ProvisionOperationRequest{}, fmt.Errorf("decode provisioning request: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ProvisionOperationRequest{}, fmt.Errorf("provisioning request has trailing data: %w", err)
	}
	if err := validateProvisionOperationRequest(request); err != nil {
		return ProvisionOperationRequest{}, err
	}

	return request, nil
}

func validateProvisionOperationRequest(request ProvisionOperationRequest) error {
	if request.ProtocolVersion != 1 {
		return errors.New("unsupported provisioning protocol version")
	}

	switch request.Operation {
	case "install_agent":
		if request.Release == nil || request.Enrollment != nil || len(request.Applications) < 1 || len(request.Applications) > 20 {
			return errors.New("install_agent requires release material and 1 to 20 application mappings only")
		}
		if strings.TrimSpace(request.Release.ManifestBase64) == "" ||
			strings.TrimSpace(request.Release.SignatureBase64) == "" ||
			strings.TrimSpace(request.Release.ArtifactPath) == "" {
			return errors.New("signed Agent release request is incomplete")
		}
		if !filepath.IsAbs(request.Release.ArtifactPath) || filepath.Clean(request.Release.ArtifactPath) != request.Release.ArtifactPath {
			return errors.New("Agent artifact path must be absolute and canonical")
		}
		seenKeys := make(map[string]struct{}, len(request.Applications))
		seenUIDs := make(map[int]struct{}, len(request.Applications))
		seenPaths := make([]string, 0, len(request.Applications))
		for _, application := range request.Applications {
			if application.ApplicationKey == "" || len(application.ApplicationKey) > 100 ||
				!filepath.IsAbs(application.BasePath) || filepath.Clean(application.BasePath) != application.BasePath ||
				application.BasePath == string(filepath.Separator) {
				return errors.New("application key and canonical absolute base path are required")
			}
			if application.RuntimeUID < 1 || application.RuntimeGID < 1 {
				return errors.New("application runtime UID and GID must be non-root positive integers")
			}
			if _, exists := seenKeys[application.ApplicationKey]; exists {
				return errors.New("application mappings contain duplicate application keys")
			}
			if _, exists := seenUIDs[application.RuntimeUID]; exists {
				return errors.New("application runtime UIDs must be distinct for credential isolation")
			}
			for _, existingPath := range seenPaths {
				if application.BasePath == existingPath ||
					strings.HasPrefix(application.BasePath, existingPath+string(filepath.Separator)) ||
					strings.HasPrefix(existingPath, application.BasePath+string(filepath.Separator)) {
					return errors.New("application base paths must not overlap")
				}
			}
			seenKeys[application.ApplicationKey] = struct{}{}
			seenUIDs[application.RuntimeUID] = struct{}{}
			seenPaths = append(seenPaths, application.BasePath)
		}
	case "enroll_agent":
		if request.Release != nil || len(request.Applications) != 0 || request.Enrollment == nil {
			return errors.New("enroll_agent accepts only the enrollment manifest and one-time token")
		}
		if strings.TrimSpace(request.Enrollment.ManifestBase64) == "" ||
			!enrollmentTokenPattern.MatchString(request.Enrollment.Token) {
			return errors.New("enroll_agent enrollment manifest or one-time token is invalid")
		}
	case "start_agent":
		if request.Release != nil || len(request.Applications) != 0 || request.Enrollment != nil {
			return errors.New("start_agent accepts no caller-supplied fields")
		}
	default:
		return errors.New("unsupported provisioning operation")
	}

	return nil
}

func RunPrivileged(reader io.Reader, writer io.Writer, errorWriter io.Writer) int {
	response := HelperResponse{
		ProtocolVersion:  1,
		Phase:            "request_validation",
		EnrollmentStatus: "not_started",
		RetrySafe:        true,
		AgentVersion:     "unknown",
	}

	if os.Geteuid() != 0 {
		return writeOperationFailure(writer, errorWriter, response, errors.New("NADI provisioning helper requires root."))
	}

	request, err := DecodeProvisionOperationRequest(reader)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	switch request.Operation {
	case "install_agent":
		return runInstallAgentOperation(request, response, writer, errorWriter)
	case "enroll_agent":
		return runEnrollAgentOperation(request, response, writer, errorWriter)
	case "start_agent":
		return runStartAgentOperation(response, writer, errorWriter)
	default:
		return writeOperationFailure(writer, errorWriter, response, errors.New("unsupported provisioning operation"))
	}
}

func runInstallAgentOperation(request ProvisionOperationRequest, response HelperResponse, writer io.Writer, errorWriter io.Writer) int {
	response.ApplicationCount = len(request.Applications)
	response.Phase = "release_verification"

	releaseManifestJSON, err := base64.StdEncoding.Strict().DecodeString(request.Release.ManifestBase64)
	if err != nil || len(releaseManifestJSON) == 0 || len(releaseManifestJSON) > maximumManifestBytes {
		return writeOperationFailure(writer, errorWriter, response, errors.New("signed release manifest is invalid or too large"))
	}

	releaseManifest, err := VerifySignedRelease(releaseManifestJSON, request.Release.SignatureBase64)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	artifact, err := SelectReleaseArtifact(releaseManifest, runtime.GOARCH)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if filepath.Base(request.Release.ArtifactPath) != artifact.Filename {
		return writeOperationFailure(writer, errorWriter, response, errors.New("staged Agent artifact filename does not match the signed release manifest"))
	}

	legacyRequest := ProvisionRequest{
		Release: ProvisionReleaseRequest{
			ArtifactPath: request.Release.ArtifactPath,
		},
		Applications: request.Applications,
	}
	if err := validateApplicationTargets(legacyRequest); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := validateStagedArtifactOwner(legacyRequest); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := VerifyReleaseArtifact(request.Release.ArtifactPath, artifact); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	attemptExists, attemptErr := hasProvisionEnrollmentAttempt()
	if attemptErr != nil {
		response.Phase = "existing_installation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment attempt metadata cannot be safely inspected"))
	}
	if attemptExists {
		response.Phase = "existing_installation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("an enrollment attempt already exists; do not retry"))
	}
	if err := rejectExistingAgentState(); err != nil {
		response.Phase = "existing_installation"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	response.Phase = "os_provisioning"
	identity, err := ensureAgentAccount()
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := prepareAgentDirectories(identity); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := installAgentAssets(request.Release.ArtifactPath, artifact.SHA256); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	inventory := provisionInventory{
		ProtocolVersion: 1,
		AgentVersion:    releaseManifest.Version,
		Applications:    request.Applications,
	}
	inventoryJSON, err := json.Marshal(inventory)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, errors.New("encode root-owned provisioning inventory"))
	}
	if err := installImmutableFile(provisionInventoryPath, inventoryJSON, 0600, 0, 0); err != nil {
		return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("install root-owned provisioning inventory: %w", err))
	}
	if _, err := runTrustedCommand("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("reload systemd units: %w", err))
	}

	response.Success = true
	response.Phase = "installed"
	response.EnrollmentStatus = "not_started"
	response.RetrySafe = true
	response.AgentVersion = releaseManifest.Version
	response.Message = "NADI Agent assets and validated application inventory installed; enrollment has not started."
	writeHelperResponse(writer, response)
	return 0
}

func runEnrollAgentOperation(request ProvisionOperationRequest, response HelperResponse, writer io.Writer, errorWriter io.Writer) int {
	inventory, err := readProvisionInventory()
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	response.ApplicationCount = len(inventory.Applications)
	response.AgentVersion = inventory.AgentVersion

	if completion, completionErr := readProvisionCompletion(); completionErr == nil {
		response.Success = true
		response.Phase = "enrolled"
		response.EnrollmentStatus = "registered"
		response.RetrySafe = false
		response.AgentVersion = completion.AgentVersion
		response.ApplicationCount = completion.ApplicationCount
		response.Message = "NADI Agent enrollment and broker configuration were already completed."
		writeHelperResponse(writer, response)
		return 0
	}

	attemptExists, attemptErr := hasProvisionEnrollmentAttempt()
	if attemptErr != nil {
		manifestDigest := sha256.Sum256(enrollmentManifestJSON)
		attempt := provisionEnrollmentAttempt{
			ProtocolVersion:  1,
			ManifestSHA256:   hex.EncodeToString(manifestDigest[:]),
			ApplicationCount: len(inventory.Applications),
		}
		attemptJSON, err := json.Marshal(attempt)
		if err != nil {
			return writeOperationFailure(writer, errorWriter, response, errors.New("encode enrollment attempt metadata"))
		}
		if err := installImmutableFile(provisionAttemptPath, attemptJSON, 0600, 0, 0); err != nil {
			return writeOperationFailure(writer, errorWriter, response, errors.New("persist enrollment attempt boundary; enrollment was not started"))
		}

		response.Phase = "enrollment"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment attempt metadata cannot be safely inspected"))
	}
	if attemptExists {
		response.Phase = "enrollment"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		response.Message = "A previous enrollment attempt has no verified completion record. Preserve Agent state and reconcile Central registration; do not retry."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}
	if _, stateErr := os.Lstat(agentStateFile); stateErr == nil {
		response.Phase = "enrollment"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		response.Message = "Existing Agent state was found without a verified completion record. Preserve it and reconcile Central registration; do not retry enrollment."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		response.Phase = "enrollment"
		return writeOperationFailure(writer, errorWriter, response, errors.New("existing Agent state cannot be safely inspected"))
	}
	enrollmentManifestJSON, err := base64.StdEncoding.Strict().DecodeString(request.Enrollment.ManifestBase64)
	if err != nil || len(enrollmentManifestJSON) == 0 || len(enrollmentManifestJSON) > maximumEnrollmentManifestBytes {
		return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment manifest is invalid or too large"))
	}
	manifest, err := decodeProvisionEnrollmentManifest(enrollmentManifestJSON)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := matchEnrollmentManifestToInventory(manifest, inventory); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	identity, err := ensureAgentAccount()
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	legacyRequest := ProvisionRequest{Applications: inventory.Applications}
	if err := validateApplicationTargets(legacyRequest); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	manifestPath, cleanupManifest, err := writeEnrollmentManifest(enrollmentManifestJSON, identity)
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	defer cleanupManifest()

	response.Phase = "enrollment"
	response.EnrollmentStatus = "unknown"
	response.RetrySafe = false

	enrollmentToken := []byte(request.Enrollment.Token)
	request.Enrollment.Token = ""
	summaryJSON, err := runAgentEnrollment(manifestPath, enrollmentToken, identity)
	if err != nil {
		response.Message = "Agent enrollment outcome is uncertain. Preserve local state and do not retry with a new token."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}

	response.EnrollmentStatus = "registered"
	response.Phase = "broker_configuration"
	brokerConfig, mappingJSON, dropIn, err := BuildBrokerArtifacts(
		uint32(identity.uid),
		uint32(identity.gid),
		legacyRequest,
		summaryJSON,
	)
	if err != nil {
		response.Message = "Central enrollment succeeded, but broker configuration could not be prepared. Preserve Agent state; do not repeat enrollment."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}
	if err := InstallBrokerArtifacts(brokerConfig, mappingJSON, dropIn); err != nil {
		response.Message = "Central enrollment succeeded, but broker artifacts could not be installed. Preserve Agent state; do not repeat enrollment."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}

	completion := provisionCompletion{
		ProtocolVersion:  1,
		AgentVersion:     inventory.AgentVersion,
		ApplicationCount: len(inventory.Applications),
		EnrollmentStatus: "registered",
	}
	completionJSON, err := json.Marshal(completion)
	if err != nil {
		response.Message = "Central enrollment succeeded, but the local completion record could not be encoded. Preserve Agent state; do not repeat enrollment."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}
	if err := installImmutableFile(provisionCompletePath, completionJSON, 0600, 0, 0); err != nil {
		response.Message = "Central enrollment succeeded, but the local completion record could not be installed. Preserve Agent state; do not repeat enrollment."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}

	response.Success = true
	response.Phase = "enrolled"
	response.EnrollmentStatus = "registered"
	response.RetrySafe = false
	response.AgentVersion = inventory.AgentVersion
	response.Message = "NADI Agent enrollment and broker configuration completed; services have not started."
	writeHelperResponse(writer, response)
	return 0
}

func runStartAgentOperation(response HelperResponse, writer io.Writer, errorWriter io.Writer) int {
	completion, err := readProvisionCompletion()
	if err != nil {
		response.Phase = "service_activation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("verified enrollment and broker completion record is missing; do not repeat enrollment"))
	}

	response.Phase = "service_activation"
	response.EnrollmentStatus = "registered"
	response.RetrySafe = false
	response.AgentVersion = completion.AgentVersion
	response.ApplicationCount = completion.ApplicationCount

	if err := verifyAgentStateFile(); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := activateAgentServices(); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}

	response.Success = true
	response.Phase = "completed"
	response.Message = "NADI handoff broker and Agent services are active; monitoring remains controlled by the Activation Gate."
	writeHelperResponse(writer, response)
	return 0
}

func decodeProvisionEnrollmentManifest(content []byte) (provisionEnrollmentManifest, error) {
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return provisionEnrollmentManifest{}, errors.New("enrollment manifest JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest provisionEnrollmentManifest
	if err := decoder.Decode(&manifest); err != nil {
		return provisionEnrollmentManifest{}, errors.New("enrollment manifest is invalid")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return provisionEnrollmentManifest{}, errors.New("enrollment manifest contains trailing data")
	}
	if len(manifest.Applications) < 1 || len(manifest.Applications) > 20 {
		return provisionEnrollmentManifest{}, errors.New("enrollment manifest must contain 1 to 20 applications")
	}
	return manifest, nil
}

func matchEnrollmentManifestToInventory(manifest provisionEnrollmentManifest, inventory provisionInventory) error {
	if len(manifest.Applications) != len(inventory.Applications) {
		return errors.New("enrollment manifest does not match the installed application inventory")
	}
	expected := make(map[string]struct{}, len(inventory.Applications))
	for _, application := range inventory.Applications {
		expected[application.ApplicationKey] = struct{}{}
	}
	for _, application := range manifest.Applications {
		if application.ApplicationKey == "" || strings.TrimSpace(application.ApplicationName) == "" ||
			strings.TrimSpace(application.Environment) == "" || len(application.ApplicationKey) > 100 ||
			len(application.ApplicationName) > 255 || len(application.Environment) > 50 ||
			len(application.FrameworkVersion) > 50 || len(application.PHPVersion) > 30 {
			return errors.New("enrollment manifest contains incomplete application identity")
		}
		parsedURL, parseErr := url.ParseRequestURI(application.BaseURL)
		if parseErr != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
			return errors.New("enrollment manifest application base_url must be an absolute HTTPS URL without user information")
		}
		if _, exists := expected[application.ApplicationKey]; !exists {
			return errors.New("enrollment manifest contains an application outside the installed inventory")
		}
		delete(expected, application.ApplicationKey)
	}
	if len(expected) != 0 {
		return errors.New("enrollment manifest is missing an installed application")
	}
	return nil
}

func readProvisionInventory() (provisionInventory, error) {
	content, err := readRootOwnedRegularFile(provisionInventoryPath, 64*1024)
	if err != nil {
		return provisionInventory{}, errors.New("root-owned provisioning inventory is missing or unsafe; run the install phase first")
	}
	var inventory provisionInventory
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil || ensureJSONEOF(decoder) != nil ||
		inventory.ProtocolVersion != 1 || inventory.AgentVersion == "" ||
		len(inventory.Applications) < 1 || len(inventory.Applications) > 20 {
		return provisionInventory{}, errors.New("root-owned provisioning inventory is invalid")
	}
	return inventory, nil
}

func hasProvisionEnrollmentAttempt() (bool, error) {
	content, err := readRootOwnedRegularFile(provisionAttemptPath, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var attempt provisionEnrollmentAttempt
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attempt); err != nil || ensureJSONEOF(decoder) != nil ||
		attempt.ProtocolVersion != 1 || attempt.ApplicationCount < 1 ||
		attempt.ApplicationCount > 20 || len(attempt.ManifestSHA256) != 64 {
		return false, errors.New("enrollment attempt metadata is invalid")
	}
	if _, err := hex.DecodeString(attempt.ManifestSHA256); err != nil {
		return false, errors.New("enrollment attempt manifest digest is invalid")
	}

	return true, nil
}

func readProvisionCompletion() (provisionCompletion, error) {
	content, err := readRootOwnedRegularFile(provisionCompletePath, 4096)
	if err != nil {
		return provisionCompletion{}, err
	}
	var completion provisionCompletion
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&completion); err != nil || ensureJSONEOF(decoder) != nil ||
		completion.ProtocolVersion != 1 || completion.AgentVersion == "" ||
		completion.ApplicationCount < 1 || completion.ApplicationCount > 20 ||
		completion.EnrollmentStatus != "registered" {
		return provisionCompletion{}, errors.New("provisioning completion record is invalid")
	}
	return completion, nil
}

func verifyAgentStateFile() error {
	metadata, err := os.Lstat(agentStateFile)
	if err != nil {
		return errors.New("Agent state is missing; refusing to start services")
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return errors.New("Agent state path is unsafe; refusing to start services")
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	account, accountErr := user.Lookup(agentAccountName)
	if !ok || accountErr != nil || metadata.Mode().Perm()&0077 != 0 {
		return errors.New("Agent state must be private and the dedicated NADI runtime account must be verifiable")
	}
	expectedUID, parseErr := strconv.Atoi(account.Uid)
	if parseErr != nil || expectedUID < 1 || stat.Uid != uint32(expectedUID) {
		return errors.New("Agent state ownership does not match the dedicated non-root runtime account")
	}
	return nil
}

func writeOperationFailure(writer io.Writer, errorWriter io.Writer, response HelperResponse, err error) int {
	response.Success = false
	response.Message = safeHelperMessage(err)
	writeHelperResponse(writer, response)
	fmt.Fprintln(errorWriter, response.Message)
	return 1
}
