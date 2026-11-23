package handoffbroker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	MaximumRequestBytes      = 16 * 1024
	MaximumResponseBytes     = 4 * 1024
	MaximumCredentialBytes   = 4 * 1024
	MaximumAssertionLifetime = 5 * time.Minute
	MaximumClockSkew         = 30 * time.Second
)

var allowedGrantCapabilities = map[string]struct{}{
	"server_metrics":       {},
	"application_metrics":  {},
	"database_monitoring":  {},
	"queue_monitoring":     {},
	"scheduler_monitoring": {},
	"application_logs":     {},
}

type Config struct {
	SchemaVersion int       `json:"schema_version"`
	AgentUID      uint32    `json:"agent_uid"`
	AgentGID      uint32    `json:"agent_gid"`
	Applications  []Mapping `json:"applications"`
}

type Mapping struct {
	ApplicationID       string `json:"application_id"`
	ApplicationKey      string `json:"application_key"`
	BasePath            string `json:"base_path"`
	RuntimeUID          int    `json:"runtime_uid"`
	RuntimeGID          int    `json:"runtime_gid"`
	CredentialFile      string `json:"credential_file"`
	ActivationStateFile string `json:"activation_state_file"`
}

type Request struct {
	ProtocolVersion   int      `json:"protocol_version"`
	Operation         string   `json:"operation"`
	ApplicationID     string   `json:"application_id"`
	ApplicationKey    string   `json:"application_key"`
	Credential        string   `json:"credential,omitempty"`
	ActivationState   string   `json:"activation_state,omitempty"`
	MonitoringEnabled bool     `json:"monitoring_enabled,omitempty"`
	GrantAcknowledged bool     `json:"grant_acknowledged,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
	ObservedAt        string   `json:"observed_at,omitempty"`
	ValidUntil        string   `json:"valid_until,omitempty"`
}

type Response struct {
	ProtocolVersion   int    `json:"protocol_version"`
	Success           bool   `json:"success"`
	ApplicationID     string `json:"application_id,omitempty"`
	CredentialVersion int    `json:"credential_version,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
}

type Server struct {
	socketPath string
	config     Config
	mappings   map[string]Mapping
	now        func() time.Time
}

func LoadConfig(path string) (Config, error) {
	if err := ensureRootOwnedDirectory(filepath.Dir(path)); err != nil {
		return Config{}, fmt.Errorf("broker mapping directory is unsafe: %w", err)
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("inspect broker mapping file: %w", err)
	}

	if !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 {
		return Config{}, errors.New("broker mapping file must be a regular non-symlink file")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || metadata.Mode().Perm() != 0600 || metadata.Size() > MaximumRequestBytes {
		return Config{}, errors.New("broker mapping file ownership, permissions, or size are invalid")
	}

	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Config{}, fmt.Errorf("open broker mapping file without following symlinks: %w", err)
	}
	mappingFile := os.NewFile(uintptr(descriptor), path)
	defer mappingFile.Close()

	openedMetadata, err := mappingFile.Stat()
	if err != nil || !openedMetadata.Mode().IsRegular() || openedMetadata.Size() > MaximumRequestBytes {
		return Config{}, errors.New("opened broker mapping file metadata is invalid")
	}

	openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != 0 || openedStat.Gid != 0 || openedMetadata.Mode().Perm() != 0600 {
		return Config{}, errors.New("opened broker mapping file ownership or permissions are invalid")
	}

	content, err := io.ReadAll(io.LimitReader(mappingFile, MaximumRequestBytes+1))
	if err != nil || len(content) > MaximumRequestBytes {
		return Config{}, errors.New("broker mapping file could not be read within the size limit")
	}

	if err := rejectDuplicateJSONKeys(content); err != nil {
		return Config{}, fmt.Errorf("broker mapping file JSON is invalid: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode broker mapping file: %w", err)
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return Config{}, err
	}

	if err := validateConfig(config); err != nil {
		return Config{}, err
	}

	return config, nil
}

func NewServer(socketPath string, config Config) (*Server, error) {
	if socketPath != "/run/nadi-agent/credential-handoff.sock" {
		return nil, errors.New("broker socket path must use the fixed NADI handoff location")
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	mappings := make(map[string]Mapping, len(config.Applications))
	for _, mapping := range config.Applications {
		mappings[mapping.ApplicationID] = mapping
	}

	return &Server{
		socketPath: socketPath,
		config:     config,
		mappings:   mappings,
		now:        time.Now,
	}, nil
}

func (s *Server) ListenAndServe() error {
	if os.Geteuid() != 0 {
		return errors.New("NADI handoff broker must run as root")
	}

	socketDirectory := filepath.Dir(s.socketPath)
	if err := ensureNoSymlinkPath("/run"); err != nil {
		return err
	}

	if err := os.Mkdir(socketDirectory, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create broker socket directory: %w", err)
	}

	socketMetadata, err := os.Lstat(socketDirectory)
	if err != nil || socketMetadata.Mode()&os.ModeSymlink != 0 || !socketMetadata.IsDir() {
		return errors.New("broker socket directory is not a safe directory")
	}

	if err := os.Chown(socketDirectory, 0, 0); err != nil {
		return fmt.Errorf("set broker socket directory group: %w", err)
	}

	if err := os.Chmod(socketDirectory, 0711); err != nil {
		return fmt.Errorf("secure broker socket directory: %w", err)
	}

	if err := ensureRootOwnedDirectory(socketDirectory); err != nil {
		return err
	}

	if metadata, err := os.Lstat(s.socketPath); err == nil {
		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok || metadata.Mode()&os.ModeSocket == 0 || stat.Uid != 0 {
			return errors.New("existing broker socket path is not a root-owned socket")
		}
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("remove stale broker socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect broker socket path: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on broker Unix socket: %w", err)
	}
	defer listener.Close()

	if err := os.Chown(s.socketPath, 0, int(s.config.AgentGID)); err != nil {
		return fmt.Errorf("set broker socket ownership: %w", err)
	}

	if err := os.Chmod(s.socketPath, 0660); err != nil {
		return fmt.Errorf("secure broker socket permissions: %w", err)
	}

	const maximumConcurrentConnections = 16
	connections := make(chan struct{}, maximumConcurrentConnections)

	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return fmt.Errorf("accept broker connection: %w", acceptErr)
		}

		select {
		case connections <- struct{}{}:
			go func() {
				defer func() {
					<-connections
				}()
				s.handleConnection(connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) handleConnection(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))

	peerUID, err := unixPeerUID(connection)
	if err != nil || peerUID != s.config.AgentUID {
		s.writeResponse(connection, Response{
			ProtocolVersion: 1,
			Success:         false,
			ErrorCode:       "peer_not_authorized",
		})
		return
	}

	requestBytes, err := readBoundedLine(connection, MaximumRequestBytes)
	if err != nil {
		s.writeResponse(connection, Response{
			ProtocolVersion: 1,
			Success:         false,
			ErrorCode:       "invalid_request",
		})
		return
	}

	request, err := decodeRequest(requestBytes)
	if err != nil {
		s.writeResponse(connection, Response{
			ProtocolVersion: 1,
			Success:         false,
			ErrorCode:       "invalid_request",
		})
		return
	}

	response := s.process(request)
	s.writeResponse(connection, response)
}

func (s *Server) process(request Request) Response {
	response := Response{
		ProtocolVersion: 1,
		Success:         false,
		ApplicationID:   request.ApplicationID,
	}

	if request.ProtocolVersion != 1 {
		response.ErrorCode = "unsupported_protocol_version"
		return response
	}

	mapping, found := s.mappings[request.ApplicationID]
	if !found || mapping.ApplicationKey != request.ApplicationKey {
		response.ErrorCode = "application_mapping_not_found"
		return response
	}

	switch request.Operation {
	case "publish_application_credential":
		if request.Credential == "" || len(request.Credential) > MaximumCredentialBytes {
			response.ErrorCode = "invalid_credential"
			return response
		}

		if err := atomicWriteFile(
			mapping.CredentialFile,
			[]byte(request.Credential),
			mapping.RuntimeUID,
			mapping.RuntimeGID,
			0600,
		); err != nil {
			response.ErrorCode = "credential_publish_failed"
			return response
		}

		response.Success = true
		response.CredentialVersion = 1
		return response

	case "publish_activation_state":
		if err := validateActivationRequest(request, s.now()); err != nil {
			response.ErrorCode = "invalid_activation_state"
			return response
		}

		payload, err := json.Marshal(struct {
			ProtocolVersion   int      `json:"protocol_version"`
			ApplicationID     string   `json:"application_id"`
			ApplicationKey    string   `json:"application_key"`
			ActivationState   string   `json:"activation_state"`
			MonitoringEnabled bool     `json:"monitoring_enabled"`
			GrantAcknowledged bool     `json:"grant_acknowledged"`
			Capabilities      []string `json:"capabilities"`
			ObservedAt        string   `json:"observed_at"`
			ValidUntil        string   `json:"valid_until"`
		}{
			ProtocolVersion:   request.ProtocolVersion,
			ApplicationID:     request.ApplicationID,
			ApplicationKey:    request.ApplicationKey,
			ActivationState:   request.ActivationState,
			MonitoringEnabled: request.MonitoringEnabled,
			GrantAcknowledged: request.GrantAcknowledged,
			Capabilities:      request.Capabilities,
			ObservedAt:        request.ObservedAt,
			ValidUntil:        request.ValidUntil,
		})
		if err != nil {
			response.ErrorCode = "activation_state_encode_failed"
			return response
		}

		if err := ensureBridgeStateDirectory(); err != nil {
			response.ErrorCode = "activation_state_directory_invalid"
			return response
		}

		if err := ensureMonotonicAssertion(mapping.ActivationStateFile, request); err != nil {
			response.ErrorCode = "activation_state_stale"
			return response
		}

		if err := atomicWriteFile(
			mapping.ActivationStateFile,
			payload,
			0,
			mapping.RuntimeGID,
			0640,
		); err != nil {
			response.ErrorCode = "activation_state_publish_failed"
			return response
		}

		response.Success = true
		return response

	default:
		response.ErrorCode = "unsupported_operation"
		return response
	}
}

func ensureMonotonicAssertion(path string, request Request) error {
	metadata, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing activation assertion is not a regular file")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || metadata.Mode().Perm()&0022 != 0 || metadata.Size() > MaximumRequestBytes {
		return errors.New("existing activation assertion metadata is invalid")
	}

	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}

	assertionFile := os.NewFile(uintptr(descriptor), path)
	defer assertionFile.Close()

	openedMetadata, err := assertionFile.Stat()
	if err != nil || !openedMetadata.Mode().IsRegular() {
		return errors.New("existing activation assertion changed while opening")
	}

	openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
	if !ok || openedStat.Uid != 0 || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return errors.New("existing activation assertion identity changed while opening")
	}

	content, err := io.ReadAll(io.LimitReader(assertionFile, MaximumRequestBytes+1))
	if err != nil || len(content) > MaximumRequestBytes {
		return errors.New("existing activation assertion exceeds the size limit")
	}

	var previous struct {
		ApplicationID  string `json:"application_id"`
		ApplicationKey string `json:"application_key"`
		ObservedAt     string `json:"observed_at"`
	}

	if err := json.Unmarshal(content, &previous); err != nil {
		return errors.New("existing activation assertion is malformed")
	}

	if previous.ApplicationID != request.ApplicationID || previous.ApplicationKey != request.ApplicationKey {
		return errors.New("existing activation assertion identity does not match the mapping")
	}

	return validateMonotonicObservation(previous.ObservedAt, request.ObservedAt)
}

func validateMonotonicObservation(previous string, next string) error {
	previousTime, err := time.Parse(time.RFC3339, previous)
	if err != nil {
		return errors.New("existing activation observation timestamp is invalid")
	}

	nextTime, err := time.Parse(time.RFC3339, next)
	if err != nil {
		return errors.New("new activation observation timestamp is invalid")
	}

	if !nextTime.After(previousTime) {
		return errors.New("activation assertion update is not newer than the existing assertion")
	}

	return nil
}

func validateActivationRequest(request Request, now time.Time) error {
	allowedStates := map[string]struct{}{
		"pending_approval":   {},
		"pending_activation": {},
		"active":             {},
		"suspended":          {},
		"revoked":            {},
		"unknown":            {},
	}

	if _, found := allowedStates[request.ActivationState]; !found {
		return errors.New("activation state is not allowed")
	}

	if request.ActivationState == "active" {
		if !request.MonitoringEnabled || !request.GrantAcknowledged || len(request.Capabilities) == 0 {
			return errors.New("active assertion requires monitoring, acknowledgement, and capabilities")
		}
	} else if request.MonitoringEnabled || request.GrantAcknowledged || len(request.Capabilities) != 0 {
		return errors.New("inactive assertion must not grant monitoring capabilities")
	}

	if request.Capabilities == nil {
		return errors.New("capabilities must be an explicit JSON array")
	}

	seen := make(map[string]struct{}, len(request.Capabilities))
	for _, capability := range request.Capabilities {
		if _, allowed := allowedGrantCapabilities[capability]; !allowed {
			return errors.New("unknown Central grant capability")
		}
		if _, duplicate := seen[capability]; duplicate {
			return errors.New("duplicate Central grant capability")
		}
		seen[capability] = struct{}{}
	}

	observedAt, err := time.Parse(time.RFC3339, request.ObservedAt)
	if err != nil {
		return errors.New("observed_at timestamp is invalid")
	}

	validUntil, err := time.Parse(time.RFC3339, request.ValidUntil)
	if err != nil {
		return errors.New("valid_until timestamp is invalid")
	}

	if observedAt.After(now.Add(MaximumClockSkew)) ||
		!validUntil.After(now) ||
		!validUntil.After(observedAt) ||
		validUntil.Sub(observedAt) > MaximumAssertionLifetime {
		return errors.New("activation assertion timestamps are outside the allowed window")
	}

	return nil
}

func atomicWriteFile(path string, content []byte, uid int, gid int, mode os.FileMode) error {
	if !filepath.IsAbs(path) {
		return errors.New("destination path must be absolute")
	}

	parent := filepath.Dir(path)
	if err := ensureRootOwnedDirectory(parent); err != nil {
		return err
	}

	if metadata, err := os.Lstat(path); err == nil {
		if !metadata.Mode().IsRegular() || metadata.Mode()&os.ModeSymlink != 0 {
			return errors.New("destination exists and is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temporary, err := os.CreateTemp(parent, ".nadi-handoff-*.tmp")
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}

	if err := temporary.Chown(uid, gid); err != nil {
		temporary.Close()
		return err
	}

	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}

	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}

	if err := temporary.Close(); err != nil {
		return err
	}

	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}

	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer directory.Close()

	return directory.Sync()
}

func ensureNoSymlinkPath(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("directory path must be absolute")
	}

	current := string(os.PathSeparator)
	for _, segment := range strings.Split(strings.TrimPrefix(path, string(os.PathSeparator)), string(os.PathSeparator)) {
		if segment == "" {
			continue
		}
		current = filepath.Join(current, segment)

		metadata, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect destination directory: %w", err)
		}

		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
			return errors.New("destination directory contains a symlink or non-directory component")
		}
	}

	return nil
}

func ensureBridgeStateDirectory() error {
	parent := "/run/nadi-agent"
	if err := ensureRootOwnedDirectory(parent); err != nil {
		return err
	}

	directory := filepath.Join(parent, "bridge-state")
	if err := os.Mkdir(directory, 0711); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create Bridge activation state directory: %w", err)
	}

	metadata, err := os.Lstat(directory)
	if err != nil || metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
		return errors.New("Bridge activation state path is not a safe directory")
	}

	if err := os.Chown(directory, 0, 0); err != nil {
		return fmt.Errorf("set Bridge activation state directory ownership: %w", err)
	}

	if err := os.Chmod(directory, 0711); err != nil {
		return fmt.Errorf("secure Bridge activation state directory: %w", err)
	}

	return ensureRootOwnedDirectory(directory)
}

func ensureRootOwnedDirectory(path string) error {
	if err := ensureNoSymlinkPath(path); err != nil {
		return err
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		return err
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || metadata.Mode().Perm()&0022 != 0 {
		return errors.New("directory must be root-owned and not group/other writable")
	}

	return nil
}

func readBoundedLine(connection net.Conn, maximum int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(connection, maximum+1))
	if err != nil {
		return nil, err
	}

	if len(content) == 0 || int64(len(content)) > maximum || content[len(content)-1] != '\n' {
		return nil, errors.New("request must be one bounded newline-terminated JSON object")
	}

	return bytes.TrimSuffix(content, []byte("\n")), nil
}

func decodeRequest(content []byte) (Request, error) {
	if !utf8.Valid(content) {
		return Request{}, errors.New("request must be valid UTF-8")
	}

	if err := rejectDuplicateJSONKeys(content); err != nil {
		return Request{}, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil || fields == nil {
		return Request{}, errors.New("request must be a JSON object")
	}

	operationBytes := fields["operation"]
	var operation string
	if err := json.Unmarshal(operationBytes, &operation); err != nil {
		return Request{}, errors.New("request operation is required")
	}

	allowedFields := map[string]struct{}{
		"protocol_version": {},
		"operation":        {},
		"application_id":   {},
		"application_key":  {},
	}
	switch operation {
	case "publish_application_credential":
		allowedFields["credential"] = struct{}{}
	case "publish_activation_state":
		allowedFields["activation_state"] = struct{}{}
		allowedFields["monitoring_enabled"] = struct{}{}
		allowedFields["grant_acknowledged"] = struct{}{}
		allowedFields["capabilities"] = struct{}{}
		allowedFields["observed_at"] = struct{}{}
		allowedFields["valid_until"] = struct{}{}
	default:
		return Request{}, errors.New("request operation is not supported")
	}

	for field := range fields {
		if _, allowed := allowedFields[field]; !allowed {
			return Request{}, fmt.Errorf("field %q is not allowed for this operation", field)
		}
	}

	for field := range allowedFields {
		if _, exists := fields[field]; !exists {
			return Request{}, fmt.Errorf("required request field %q is missing", field)
		}
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return Request{}, err
	}

	return request, nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()

	if err := consumeJSONValue(decoder); err != nil {
		return err
	}

	return ensureJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}

			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}

			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		_, err := decoder.Token()
		return err

	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		_, err := decoder.Token()
		return err

	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON contains trailing values")
		}
		return err
	}

	return nil
}

func unixPeerUID(connection net.Conn) (uint32, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("connection is not a Unix socket")
	}

	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}

	var credentials *syscall.Ucred
	var controlError error

	if err := rawConnection.Control(func(fd uintptr) {
		credentials, controlError = syscall.GetsockoptUcred(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_PEERCRED,
		)
	}); err != nil {
		return 0, err
	}

	if controlError != nil {
		return 0, controlError
	}

	if credentials == nil {
		return 0, errors.New("kernel peer credentials are unavailable")
	}

	return credentials.Uid, nil
}

func validateConfig(config Config) error {
	if config.SchemaVersion != 1 || config.AgentUID == 0 || config.AgentGID == 0 {
		return errors.New("broker mapping schema or Agent identity is invalid")
	}

	if len(config.Applications) == 0 || len(config.Applications) > 20 {
		return errors.New("broker mapping must contain between 1 and 20 applications")
	}

	seenIDs := make(map[string]struct{}, len(config.Applications))
	seenKeys := make(map[string]struct{}, len(config.Applications))
	seenCredentialPaths := make(map[string]struct{}, len(config.Applications))
	seenActivationPaths := make(map[string]struct{}, len(config.Applications))

	for _, mapping := range config.Applications {
		if mapping.ApplicationID == "" || mapping.ApplicationKey == "" {
			return errors.New("application mapping identity must not be empty")
		}

		if _, duplicate := seenIDs[mapping.ApplicationID]; duplicate {
			return errors.New("duplicate application_id in broker mapping")
		}
		if _, duplicate := seenKeys[mapping.ApplicationKey]; duplicate {
			return errors.New("duplicate application_key in broker mapping")
		}

		seenIDs[mapping.ApplicationID] = struct{}{}
		seenKeys[mapping.ApplicationKey] = struct{}{}

		if mapping.RuntimeUID < 1 || mapping.RuntimeGID < 1 {
			return errors.New("application runtime UID and GID must be positive")
		}

		if !filepath.IsAbs(mapping.BasePath) ||
			!filepath.IsAbs(mapping.CredentialFile) ||
			!filepath.IsAbs(mapping.ActivationStateFile) {
			return errors.New("application mapping paths must be absolute")
		}

		basePath := filepath.Clean(mapping.BasePath)
		credentialPath := filepath.Clean(mapping.CredentialFile)
		activationPath := filepath.Clean(mapping.ActivationStateFile)

		if basePath != mapping.BasePath || credentialPath != mapping.CredentialFile || activationPath != mapping.ActivationStateFile {
			return errors.New("application mapping paths must already be canonical")
		}

		expectedCredentialPath := filepath.Join(
			"/var/lib/nadi-bridge",
			mapping.ApplicationID,
			"credential",
		)
		if credentialPath != expectedCredentialPath {
			return errors.New("credential destination must use the fixed root-owned NADI Bridge credential directory")
		}

		if filepath.Dir(activationPath) != "/run/nadi-agent/bridge-state" {
			return errors.New("activation assertion destination is outside the fixed runtime directory")
		}

		if _, duplicate := seenCredentialPaths[credentialPath]; duplicate {
			return errors.New("multiple applications share a credential destination")
		}
		if _, duplicate := seenActivationPaths[activationPath]; duplicate {
			return errors.New("multiple applications share an activation assertion destination")
		}

		seenCredentialPaths[credentialPath] = struct{}{}
		seenActivationPaths[activationPath] = struct{}{}
	}

	return nil
}

func (s *Server) writeResponse(connection net.Conn, response Response) {
	payload, err := json.Marshal(response)
	if err != nil || len(payload) > MaximumResponseBytes {
		return
	}

	_, _ = connection.Write(append(payload, '\n'))
}
