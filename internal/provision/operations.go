package provision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
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
	ArtifactSHA256  string                 `json:"artifact_sha256"`
	Applications    []ProvisionApplication `json:"applications"`
}

type provisionCompletion struct {
	ProtocolVersion  int    `json:"protocol_version"`
	AgentVersion     string `json:"agent_version"`
	ApplicationCount int    `json:"application_count"`
	EnrollmentStatus string `json:"enrollment_status"`
	AgentInstanceID  string `json:"agent_instance_id"`
	AgentID          string `json:"agent_id"`
	ServerID         string `json:"server_id"`
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
	if err := validateProvisionOperationFieldSet(content, request.Operation); err != nil {
		return ProvisionOperationRequest{}, err
	}
	if err := validateProvisionOperationRequest(request); err != nil {
		return ProvisionOperationRequest{}, err
	}

	return request, nil
}

func validateProvisionOperationFieldSet(content []byte, operation string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return errors.New("provisioning request must be a JSON object")
	}

	allowed := map[string]struct{}{
		"protocol_version": {},
		"operation":        {},
	}
	switch operation {
	case "install_agent":
		allowed["release"] = struct{}{}
		allowed["applications"] = struct{}{}
	case "enroll_agent":
		allowed["enrollment"] = struct{}{}
	case "start_agent":
	default:
		return errors.New("unsupported provisioning operation")
	}

	for field := range fields {
		if _, exists := allowed[field]; !exists {
			return fmt.Errorf("field %q is not allowed for operation %q", field, operation)
		}
	}
	return nil
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

	unlock, err := acquireProvisionLock()
	if err != nil {
		response.Phase = "operation_lock"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	defer unlock()

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

	alreadyInstalled, err := recoverProvisionJournalForInstall(
		releaseManifest.Version,
		artifact.SHA256,
		request.Applications,
	)
	if err != nil {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if alreadyInstalled {
		response.Success = true
		response.Phase = "installed"
		response.EnrollmentStatus = "not_started"
		response.RetrySafe = true
		response.AgentVersion = releaseManifest.Version
		response.Message = "The previous installation transaction was already committed and its inventory matches this request."
		writeHelperResponse(writer, response)
		return 0
	}

	attemptExists, attemptErr := hasProvisionEnrollmentAttempt()
	if attemptErr != nil {
		response.Phase = "existing_installation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment attempt metadata cannot be safely inspected"))
	}
	if attemptExists {
		inventory, inventoryErr := readProvisionInventory()
		completion, completionErr := readProvisionCompletion()
		if inventoryErr == nil && completionErr == nil &&
			inventory.AgentVersion == releaseManifest.Version &&
			inventory.ArtifactSHA256 == artifact.SHA256 &&
			sameApplicationInventory(inventory.Applications, request.Applications) &&
			completion.AgentVersion == inventory.AgentVersion &&
			completion.ApplicationCount == len(inventory.Applications) {
			if err := verifyExistingEnrollmentIdentity(request.Applications, inventory.ArtifactSHA256, completion); err == nil {
				response.Success = true
				response.Phase = "enrolled"
				response.EnrollmentStatus = "registered"
				response.RetrySafe = false
				response.AgentVersion = completion.AgentVersion
				response.ApplicationCount = completion.ApplicationCount
				response.Message = "Existing NADI installation and Agent identity are verified; continue with the remaining lifecycle operation."
				writeHelperResponse(writer, response)
				return 0
			}
		}
		response.Phase = "existing_installation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("an enrollment attempt exists without a matching verified completion record; reconcile before retrying"))
	}

	if _, stateErr := os.Lstat(agentStateFile); stateErr == nil {
		response.Phase = "identity_restore"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false

		if err := restoreExistingAgentIdentity(request, releaseManifest.Version, artifact.SHA256); err != nil {
			response.Phase = "recovery_required"
			return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("existing Agent identity could not be safely restored: %w", err))
		}

		response.Success = true
		response.Phase = "enrolled"
		response.EnrollmentStatus = "registered"
		response.RetrySafe = false
		response.AgentVersion = releaseManifest.Version
		response.Message = "Existing NADI Agent identity was verified on this server and restored without a new enrollment."
		writeHelperResponse(writer, response)
		return 0
	} else if !errors.Is(stateErr, os.ErrNotExist) {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("existing Agent state cannot be safely inspected"))
	}

	if _, completionErr := os.Lstat(provisionCompletePath); completionErr == nil {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("a prior enrollment completion record exists but Agent state is missing; restore or reconcile identity before any new enrollment"))
	} else if !errors.Is(completionErr, os.ErrNotExist) {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("prior enrollment completion metadata cannot be safely inspected"))
	}

	store, journal, err := newProvisionJournal(provisionJournalPath)
	if err != nil {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "not_started"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("start provisioning transaction journal: %w", err))
	}

	rollbackFailure := func(cause error) int {
		if rollbackErr := store.Rollback(&journal, provisionJournalRollbackRoots); rollbackErr != nil {
			response.Phase = "recovery_required"
			response.EnrollmentStatus = "not_started"
			response.RetrySafe = false
			return writeOperationFailure(
				writer,
				errorWriter,
				response,
				fmt.Errorf("provisioning failed: %v; rollback requires manual recovery: %w", cause, rollbackErr),
			)
		}
		if removeErr := removeProvisionJournal(store, "rolled_back"); removeErr != nil {
			response.Phase = "recovery_required"
			response.EnrollmentStatus = "not_started"
			response.RetrySafe = false
			return writeOperationFailure(
				writer,
				errorWriter,
				response,
				fmt.Errorf("provisioning resources were rolled back but the journal could not be removed: %w", removeErr),
			)
		}

		response.Phase = "rolled_back"
		response.EnrollmentStatus = "not_started"
		response.RetrySafe = true
		return writeOperationFailure(
			writer,
			errorWriter,
			response,
			fmt.Errorf("provisioning failed; transaction-created files and directories were rolled back; the fixed nadi-agent account is intentionally retained: %w", cause),
		)
	}

	response.Phase = "os_provisioning"

	accountAction, err := store.AddIntent(&journal, "account", "nadi-agent")
	if err != nil {
		return rollbackFailure(fmt.Errorf("record fixed Agent account intent: %w", err))
	}
	identity, err := ensureAgentAccount()
	if err != nil {
		return rollbackFailure(fmt.Errorf("verify or create fixed Agent account: %w", err))
	}
	if err := store.MarkRetained(&journal, accountAction); err != nil {
		return rollbackFailure(fmt.Errorf("record retained fixed Agent account: %w", err))
	}

	if err := prepareAgentDirectoriesJournaled(identity, store, &journal); err != nil {
		return rollbackFailure(err)
	}
	if err := installAgentAssetsJournaled(request.Release.ArtifactPath, artifact.SHA256, store, &journal); err != nil {
		return rollbackFailure(err)
	}

	inventory := provisionInventory{
		ProtocolVersion: 1,
		AgentVersion:    releaseManifest.Version,
		ArtifactSHA256:  artifact.SHA256,
		Applications:    request.Applications,
	}
	inventoryJSON, err := json.Marshal(inventory)
	if err != nil {
		return rollbackFailure(errors.New("encode root-owned provisioning inventory"))
	}
	if err := installImmutableFileJournaled(
		provisionInventoryPath,
		inventoryJSON,
		0600,
		0,
		0,
		store,
		&journal,
	); err != nil {
		return rollbackFailure(fmt.Errorf("install root-owned provisioning inventory: %w", err))
	}

	if _, err := runTrustedCommand("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return rollbackFailure(fmt.Errorf("reload systemd units: %w", err))
	}

	if err := store.Commit(&journal); err != nil {
		return rollbackFailure(fmt.Errorf("commit provisioning transaction journal: %w", err))
	}
	if err := removeProvisionJournal(store, "committed"); err != nil {
		response.Phase = "installed"
		response.EnrollmentStatus = "not_started"
		response.RetrySafe = true
		response.AgentVersion = releaseManifest.Version
		response.Message = "Installation completed and committed; the committed journal is retained for safe recovery on the next invocation."
		writeHelperResponse(writer, response)
		return 0
	}

	response.Success = true
	response.Phase = "installed"
	response.EnrollmentStatus = "not_started"
	response.RetrySafe = true
	response.AgentVersion = releaseManifest.Version
	response.Message = "NADI Agent assets and validated application inventory installed; enrollment has not started. The transaction journal was committed and removed."
	writeHelperResponse(writer, response)
	return 0
}

func decodeEnrollmentIdentitySummary(summaryJSON []byte) (provisionCompletion, error) {
	if len(summaryJSON) == 0 || len(summaryJSON) > maximumEnrollmentSummaryBytes {
		return provisionCompletion{}, errors.New("Agent enrollment identity summary is empty or too large")
	}
	if err := rejectDuplicateJSONKeys(summaryJSON); err != nil {
		return provisionCompletion{}, errors.New("Agent enrollment identity summary is ambiguous")
	}

	decoder := json.NewDecoder(bytes.NewReader(summaryJSON))
	decoder.DisallowUnknownFields()
	var summary enrollmentSummary
	if err := decoder.Decode(&summary); err != nil || ensureJSONEOF(decoder) != nil {
		return provisionCompletion{}, errors.New("Agent enrollment identity summary is invalid")
	}
	if summary.ProtocolVersion != 1 ||
		summary.EnrollmentStatus != "registered" ||
		strings.TrimSpace(summary.AgentInstanceID) == "" ||
		strings.TrimSpace(summary.AgentID) == "" ||
		strings.TrimSpace(summary.ServerID) == "" ||
		len(summary.Applications) < 1 ||
		len(summary.Applications) > 20 {
		return provisionCompletion{}, errors.New("Agent enrollment identity summary is incomplete")
	}

	return provisionCompletion{
		EnrollmentStatus: "registered",
		AgentInstanceID:  summary.AgentInstanceID,
		AgentID:          summary.AgentID,
		ServerID:         summary.ServerID,
	}, nil
}

func verifyExistingEnrollmentIdentity(
	applications []ProvisionApplication,
	artifactSHA256 string,
	completion provisionCompletion,
) error {
	identity, err := ensureAgentAccount()
	if err != nil {
		return fmt.Errorf("verify dedicated Agent runtime account: %w", err)
	}
	if err := verifyAgentStateFile(); err != nil {
		return err
	}
	if err := verifyInstalledAgentBinaryDigest(artifactSHA256); err != nil {
		return err
	}

	summaryJSON, err := runAgentIdentityVerification(identity)
	if err != nil {
		return err
	}
	identityRecord, err := decodeEnrollmentIdentitySummary(summaryJSON)
	if err != nil {
		return err
	}
	if identityRecord.AgentInstanceID != completion.AgentInstanceID ||
		identityRecord.AgentID != completion.AgentID ||
		identityRecord.ServerID != completion.ServerID {
		return errors.New("persisted Agent identity does not match the root-owned enrollment completion record")
	}
	_, expectedMapping, expectedDropIn, err := BuildBrokerArtifacts(
		uint32(identity.uid),
		uint32(identity.gid),
		ProvisionRequest{Applications: applications},
		summaryJSON,
	)
	if err != nil {
		return fmt.Errorf("verify existing enrollment application identity: %w", err)
	}

	installedMapping, err := readRootOwnedRegularFile(brokerMappingPath, 64*1024)
	if err != nil || !bytes.Equal(installedMapping, expectedMapping) {
		return errors.New("installed Bridge mapping does not match the verified Agent identity")
	}
	installedDropIn, err := readRootOwnedRegularFile(brokerDropInPath, 64*1024)
	if err != nil || string(installedDropIn) != expectedDropIn {
		return errors.New("installed Bridge service permissions do not match the verified Agent identity")
	}

	return nil
}

func restoreExistingAgentIdentity(
	request ProvisionOperationRequest,
	releaseVersion string,
	artifactSHA256 string,
) error {
	identity, err := ensureAgentAccount()
	if err != nil {
		return fmt.Errorf("verify dedicated Agent runtime account: %w", err)
	}

	if err := verifyAgentStateFile(); err != nil {
		return err
	}

	store, journal, err := newProvisionJournalForOperation(provisionJournalPath, "restore_agent")
	if err != nil {
		return fmt.Errorf("start identity restore transaction journal: %w", err)
	}

	rollbackFailure := func(cause error) error {
		if rollbackErr := store.Rollback(&journal, provisionJournalRollbackRoots); rollbackErr != nil {
			return fmt.Errorf("identity restore failed: %v; transaction rollback requires manual recovery: %w", cause, rollbackErr)
		}
		if removeErr := removeProvisionJournal(store, "rolled_back"); removeErr != nil {
			return fmt.Errorf("identity restore failed: %v; rollback completed but its journal could not be removed: %w", cause, removeErr)
		}
		return cause
	}

	if err := prepareAgentDirectoriesJournaled(identity, store, &journal); err != nil {
		return rollbackFailure(fmt.Errorf("prepare canonical Agent directories for identity restore: %w", err))
	}

	if err := installAgentAssetsJournaled(
		request.Release.ArtifactPath,
		artifactSHA256,
		store,
		&journal,
	); err != nil {
		return rollbackFailure(fmt.Errorf("restore signed Agent assets without replacing existing files: %w", err))
	}

	if err := verifyInstalledAgentBinaryDigest(artifactSHA256); err != nil {
		return rollbackFailure(err)
	}

	summaryJSON, err := runAgentIdentityVerification(identity)
	if err != nil {
		return rollbackFailure(err)
	}

	identityRecord, err := decodeEnrollmentIdentitySummary(summaryJSON)
	if err != nil {
		return rollbackFailure(fmt.Errorf("verify existing Agent identity summary: %w", err))
	}

	completionExists := false
	if existingCompletion, completionErr := readProvisionCompletion(); completionErr == nil {
		completionExists = true
		if existingCompletion.AgentInstanceID != identityRecord.AgentInstanceID ||
			existingCompletion.AgentID != identityRecord.AgentID ||
			existingCompletion.ServerID != identityRecord.ServerID {
			return rollbackFailure(errors.New("existing Agent identity does not match the root-owned enrollment completion record"))
		}
		if existingCompletion.AgentVersion != releaseVersion ||
			existingCompletion.ApplicationCount != len(request.Applications) {
			return rollbackFailure(errors.New("RESTORE cannot change the installed Agent release or application inventory of an existing Agent identity"))
		}
	} else if !errors.Is(completionErr, os.ErrNotExist) {
		return rollbackFailure(errors.New("existing enrollment completion metadata is unsafe or invalid; reconcile identity before RESTORE"))
	}

	inventoryExists := false
	if _, inventoryStatErr := os.Lstat(provisionInventoryPath); inventoryStatErr == nil {
		inventoryExists = true
		existingInventory, inventoryErr := readProvisionInventory()
		if inventoryErr != nil {
			return rollbackFailure(errors.New("existing provisioning inventory is unsafe or invalid; reconcile identity before RESTORE"))
		}
		if existingInventory.AgentVersion != releaseVersion ||
			existingInventory.ArtifactSHA256 != artifactSHA256 ||
			!sameApplicationInventory(existingInventory.Applications, request.Applications) {
			return rollbackFailure(errors.New("RESTORE cannot replace the installed Agent release identity or application inventory"))
		}
	} else if !errors.Is(inventoryStatErr, os.ErrNotExist) {
		return rollbackFailure(errors.New("existing provisioning inventory cannot be safely inspected; reconcile identity before RESTORE"))
	}

	legacyRequest := ProvisionRequest{
		Applications: request.Applications,
	}
	brokerConfig, mappingJSON, dropIn, err := BuildBrokerArtifacts(
		uint32(identity.uid),
		uint32(identity.gid),
		legacyRequest,
		summaryJSON,
	)
	if err != nil {
		return rollbackFailure(fmt.Errorf("reconcile persisted Agent identity with the requested application inventory: %w", err))
	}

	if err := installBrokerArtifactsJournaled(
		brokerConfig,
		mappingJSON,
		dropIn,
		store,
		&journal,
	); err != nil {
		return rollbackFailure(fmt.Errorf("restore Bridge broker artifacts: %w", err))
	}

	inventory := provisionInventory{
		ProtocolVersion: 1,
		AgentVersion:    releaseVersion,
		ArtifactSHA256:  artifactSHA256,
		Applications:    request.Applications,
	}
	inventoryJSON, err := json.Marshal(inventory)
	if err != nil {
		return rollbackFailure(errors.New("encode restored provisioning inventory"))
	}
	if !inventoryExists {
		if err := installImmutableFileJournaled(
			provisionInventoryPath,
			inventoryJSON,
			0600,
			0,
			0,
			store,
			&journal,
		); err != nil {
			return rollbackFailure(fmt.Errorf("persist restored provisioning inventory: %w", err))
		}
	}

	completion := provisionCompletion{
		ProtocolVersion:  1,
		AgentVersion:     releaseVersion,
		ApplicationCount: len(request.Applications),
		EnrollmentStatus: "registered",
		AgentInstanceID:  identityRecord.AgentInstanceID,
		AgentID:          identityRecord.AgentID,
		ServerID:         identityRecord.ServerID,
	}
	completionJSON, err := json.Marshal(completion)
	if err != nil {
		return rollbackFailure(errors.New("encode restored provisioning completion record"))
	}
	if !completionExists {
		if err := installImmutableFileJournaled(
			provisionCompletePath,
			completionJSON,
			0600,
			0,
			0,
			store,
			&journal,
		); err != nil {
			return rollbackFailure(fmt.Errorf("persist restored provisioning completion record: %w", err))
		}
	}

	if _, err := runTrustedCommand("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return rollbackFailure(fmt.Errorf("reload systemd units after identity restore: %w", err))
	}

	if err := store.Commit(&journal); err != nil {
		return rollbackFailure(fmt.Errorf("commit identity restore transaction journal: %w", err))
	}
	if err := removeProvisionJournal(store, "committed"); err != nil {
		return fmt.Errorf("identity restore committed successfully but its journal is retained for safe recovery: %w", err)
	}

	return nil
}
func verifyInstalledAgentBinaryDigest(expectedSHA256 string) error {
	content, err := readRootOwnedRegularFile(agentBinaryPath, maximumArtifactBytes)
	if err != nil {
		return errors.New("existing Agent binary is missing or unsafe; identity restore requires a verified installed binary")
	}

	metadata, err := os.Lstat(agentBinaryPath)
	if err != nil {
		return err
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || metadata.Mode().Perm() != 0755 {
		return errors.New("existing Agent binary ownership or permissions are invalid")
	}

	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return errors.New("existing Agent binary does not match the verified release; automatic binary replacement is prohibited")
	}

	return nil
}

func runAgentIdentityVerification(identity helperRuntimeIdentity) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	command := exec.CommandContext(
		ctx,
		agentBinaryPath,
		"--verify-existing-identity-summary-stdout",
	)
	command.Env = []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + agentStateDirectory,
		"NADI_CENTRAL_URL=https://nadi.pesantrenalirsyad.org",
		"NADI_STATE_DIR=" + agentStateDirectory,
		"NADI_ACTIVATION_PUBLIC_KEY=" + activationPublicKeyPath,
		"NADI_ACTIVATION_KEY_ID=nadi-central-2026-01",
		"NADI_AGENT_HANDOFF_SOCKET=/run/nadi/credential-handoff.sock",
	}
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uint32(identity.uid),
			Gid:    uint32(identity.gid),
			Groups: []uint32{uint32(identity.gid)},
		},
		Setpgid: true,
	}

	var stdout boundedBuffer
	var stderr boundedBuffer
	stdout.maximum = maximumEnrollmentSummaryBytes
	stderr.maximum = 4 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, errors.New("read-only Agent identity verification timed out")
		}
		return nil, errors.New("read-only Agent identity verification failed")
	}
	if stdout.overflow {
		return nil, errors.New("verified Agent identity summary exceeded the allowed size")
	}

	summary := append([]byte(nil), stdout.buffer.Bytes()...)
	if len(summary) == 0 {
		return nil, errors.New("verified Agent identity summary is empty")
	}

	return summary, nil
}

func runEnrollAgentOperation(request ProvisionOperationRequest, response HelperResponse, writer io.Writer, errorWriter io.Writer) int {
	inventory, err := readProvisionInventory()
	if err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	response.ApplicationCount = len(inventory.Applications)
	response.AgentVersion = inventory.AgentVersion

	if completion, completionErr := readProvisionCompletion(); completionErr == nil {
		if completion.AgentVersion != inventory.AgentVersion ||
			completion.ApplicationCount != len(inventory.Applications) {
			response.Phase = "enrollment"
			response.EnrollmentStatus = "unknown"
			response.RetrySafe = false
			return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment completion record does not match the installed inventory"))
		}
		if err := verifyExistingEnrollmentIdentity(inventory.Applications, inventory.ArtifactSHA256, completion); err != nil {
			response.Phase = "recovery_required"
			response.EnrollmentStatus = "unknown"
			response.RetrySafe = false
			return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("existing enrollment identity could not be verified: %w", err))
		}
		response.Success = true
		response.Phase = "enrolled"
		response.EnrollmentStatus = "registered"
		response.RetrySafe = false
		response.AgentVersion = completion.AgentVersion
		response.ApplicationCount = completion.ApplicationCount
		response.Message = "NADI Agent enrollment and broker configuration were already completed and the persisted identity is verified."
		writeHelperResponse(writer, response)
		return 0
	}

	attemptExists, attemptErr := hasProvisionEnrollmentAttempt()
	if attemptErr != nil {
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

	enrollmentToken := []byte(request.Enrollment.Token)
	request.Enrollment.Token = ""
	summaryJSON, err := runAgentEnrollment(manifestPath, enrollmentToken, identity)
	if err != nil {
		response.Message = "Agent enrollment outcome is uncertain. Preserve local state and do not retry with a new token."
		writeHelperResponse(writer, response)
		fmt.Fprintln(errorWriter, response.Message)
		return 1
	}

	identityRecord, err := decodeEnrollmentIdentitySummary(summaryJSON)
	if err != nil {
		response.EnrollmentStatus = "registered"
		response.Phase = "broker_configuration"
		response.Message = "Central enrollment succeeded, but the persisted Agent identity summary could not be verified. Preserve Agent state; do not repeat enrollment."
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
		AgentInstanceID:  identityRecord.AgentInstanceID,
		AgentID:          identityRecord.AgentID,
		ServerID:         identityRecord.ServerID,
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
	inventory, err := readProvisionInventory()
	if err != nil || completion.AgentVersion != inventory.AgentVersion ||
		completion.ApplicationCount != len(inventory.Applications) {
		response.Phase = "service_activation"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, errors.New("enrollment completion record does not match the installed inventory"))
	}

	response.Phase = "service_activation"
	response.EnrollmentStatus = "registered"
	response.RetrySafe = false
	response.AgentVersion = completion.AgentVersion
	response.ApplicationCount = completion.ApplicationCount

	if err := verifyExistingEnrollmentIdentity(inventory.Applications, inventory.ArtifactSHA256, completion); err != nil {
		response.Phase = "recovery_required"
		response.EnrollmentStatus = "unknown"
		response.RetrySafe = false
		return writeOperationFailure(writer, errorWriter, response, fmt.Errorf("Agent identity verification failed before service activation: %w", err))
	}
	if err := verifyAgentStateFile(); err != nil {
		return writeOperationFailure(writer, errorWriter, response, err)
	}
	if err := verifyInstalledNADIAssets(); err != nil {
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

func sameApplicationInventory(installed []ProvisionApplication, requested []ProvisionApplication) bool {
	if len(installed) != len(requested) {
		return false
	}

	byKey := make(map[string]ProvisionApplication, len(installed))
	for _, application := range installed {
		if application.ApplicationKey == "" {
			return false
		}
		if _, exists := byKey[application.ApplicationKey]; exists {
			return false
		}
		byKey[application.ApplicationKey] = application
	}

	for _, application := range requested {
		existing, exists := byKey[application.ApplicationKey]
		if !exists ||
			existing.BasePath != application.BasePath ||
			existing.RuntimeUID != application.RuntimeUID ||
			existing.RuntimeGID != application.RuntimeGID {
			return false
		}
		delete(byKey, application.ApplicationKey)
	}

	return len(byKey) == 0
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
		!validSHA256Digest(inventory.ArtifactSHA256) ||
		len(inventory.Applications) < 1 || len(inventory.Applications) > 20 {
		return provisionInventory{}, errors.New("root-owned provisioning inventory is invalid")
	}
	return inventory, nil
}

func validSHA256Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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
		completion.EnrollmentStatus != "registered" ||
		completion.AgentInstanceID == "" ||
		completion.AgentID == "" ||
		completion.ServerID == "" {
		return provisionCompletion{}, errors.New("provisioning completion record is invalid")
	}
	return completion, nil
}

func verifyInstalledNADIAssets() error {
	assets := []struct {
		path string
		size int64
	}{
		{path: agentBinaryPath, size: maximumArtifactBytes},
		{path: activationPublicKeyPath, size: 64 * 1024},
		{path: agentUnitPath, size: 64 * 1024},
		{path: brokerUnitPath, size: 64 * 1024},
		{path: brokerMappingPath, size: 64 * 1024},
		{path: brokerDropInPath, size: 64 * 1024},
	}

	for _, asset := range assets {
		if _, err := readRootOwnedRegularFile(asset.path, asset.size); err != nil {
			return fmt.Errorf("required root-owned NADI asset %s is missing or unsafe", filepath.Base(asset.path))
		}
	}

	return nil
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
