package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"nadi-agent/internal/handoffbroker"
)

const (
	bridgeApplicationConfigDirectory                 = "/var/lib/nadi-bridge/config"
	bridgeApplicationConfigDirectoryMode os.FileMode = 0711
	bridgeApplicationConfigFileMode      os.FileMode = 0640
	maximumCentralSourceIPs                          = 16
)

type bridgeApplicationConfiguration struct {
	SchemaVersion       int      `json:"schema_version"`
	Enabled             bool     `json:"enabled"`
	ApplicationID       string   `json:"application_id"`
	ApplicationKey      string   `json:"application_key"`
	AllowedIPs          []string `json:"allowed_ips"`
	CredentialFile      string   `json:"credential_file"`
	ActivationStateFile string   `json:"activation_state_file"`
}

type bridgeApplicationConfigurationArtifact struct {
	Path    string
	Content []byte
	GID     int
}

// BuildBridgeApplicationConfigurations creates deterministic, non-secret
// configuration files that each Laravel runtime can read through its own GID.
func BuildBridgeApplicationConfigurations(
	config handoffbroker.Config,
	centralSourceIPs []string,
) ([]bridgeApplicationConfigurationArtifact, error) {
	if _, err := handoffbroker.NewServer("/run/nadi/credential-handoff.sock", config); err != nil {
		return nil, fmt.Errorf("validate Bridge application mapping: %w", err)
	}

	normalizedIPs, err := normalizeCentralSourceIPs(centralSourceIPs)
	if err != nil {
		return nil, err
	}

	if len(config.Applications) < 1 || len(config.Applications) > 20 {
		return nil, errors.New("Bridge configuration requires 1 to 20 registered applications")
	}

	seenGIDs := make(map[int]struct{}, len(config.Applications))
	artifacts := make([]bridgeApplicationConfigurationArtifact, 0, len(config.Applications))

	for _, application := range config.Applications {
		if application.RuntimeGID < 1 {
			return nil, errors.New("Bridge application runtime GID must be non-root")
		}
		if _, exists := seenGIDs[application.RuntimeGID]; exists {
			return nil, errors.New("Bridge application runtime GIDs must be unique for configuration isolation")
		}
		seenGIDs[application.RuntimeGID] = struct{}{}

		if !filepath.IsAbs(application.BasePath) ||
			filepath.Clean(application.BasePath) != application.BasePath ||
			application.BasePath == string(os.PathSeparator) {
			return nil, errors.New("Bridge application base path must be absolute and canonical")
		}

		configuration := bridgeApplicationConfiguration{
			SchemaVersion:       1,
			Enabled:             true,
			ApplicationID:       application.ApplicationID,
			ApplicationKey:      application.ApplicationKey,
			AllowedIPs:          normalizedIPs,
			CredentialFile:      "/var/lib/nadi-bridge/" + application.ApplicationID + "/credential",
			ActivationStateFile: "/run/nadi/bridge-state/" + application.ApplicationID + ".json",
		}

		content, err := json.MarshalIndent(configuration, "", "    ")
		if err != nil {
			return nil, fmt.Errorf("encode Bridge application configuration: %w", err)
		}
		content = append(content, '\n')

		digest := sha256.Sum256([]byte(application.BasePath))
		path := filepath.Join(
			bridgeApplicationConfigDirectory,
			hex.EncodeToString(digest[:])+".json",
		)

		artifacts = append(artifacts, bridgeApplicationConfigurationArtifact{
			Path:    path,
			Content: content,
			GID:     application.RuntimeGID,
		})
	}

	return artifacts, nil
}

func normalizeCentralSourceIPs(addresses []string) ([]string, error) {
	if len(addresses) < 1 || len(addresses) > maximumCentralSourceIPs {
		return nil, errors.New("one to sixteen infrastructure-verified Central source IP addresses are required")
	}

	normalized := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))

	for _, address := range addresses {
		parsed := net.ParseIP(address)
		if parsed == nil {
			return nil, errors.New("Central source-IP allowlist must contain exact IPv4 or IPv6 addresses")
		}
		canonicalAddress := parsed.String()
		if _, exists := seen[canonicalAddress]; exists {
			return nil, errors.New("Central source-IP allowlist contains a duplicate address")
		}

		seen[canonicalAddress] = struct{}{}
		normalized = append(normalized, canonicalAddress)
	}

	sort.Strings(normalized)

	return normalized, nil
}

func installBridgeApplicationConfigurationsJournaled(
	config handoffbroker.Config,
	centralSourceIPs []string,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if os.Geteuid() != 0 {
		return errors.New("Bridge application configuration installation requires root")
	}

	return installBridgeApplicationConfigurationsJournaledAt(
		string(os.PathSeparator),
		config,
		centralSourceIPs,
		0,
		0,
		store,
		journal,
	)
}

func installBridgeApplicationConfigurationsJournaledAt(
	root string,
	config handoffbroker.Config,
	centralSourceIPs []string,
	ownerUID int,
	directoryGID int,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("Bridge configuration installation root must be absolute and canonical")
	}
	if store == nil || journal == nil ||
		(journal.Operation != "restore_agent" && journal.Operation != "enroll_agent") {
		return errors.New("identity restore or enrollment journal is required for Bridge configuration installation")
	}

	artifacts, err := BuildBridgeApplicationConfigurations(config, centralSourceIPs)
	if err != nil {
		return err
	}

	directory := filepath.Join(root, strings.TrimPrefix(bridgeApplicationConfigDirectory, string(os.PathSeparator)))
	if err := ensureDirectoryTreeJournaled(
		root,
		directory,
		bridgeApplicationConfigDirectoryMode,
		ownerUID,
		directoryGID,
		store,
		journal,
	); err != nil {
		return fmt.Errorf("prepare Bridge application configuration directory: %w", err)
	}

	for _, artifact := range artifacts {
		destination := filepath.Join(root, strings.TrimPrefix(artifact.Path, string(os.PathSeparator)))
		if err := installImmutableFileJournaled(
			destination,
			artifact.Content,
			bridgeApplicationConfigFileMode,
			ownerUID,
			artifact.GID,
			store,
			journal,
		); err != nil {
			return fmt.Errorf("install Bridge application configuration: %w", err)
		}
	}

	return nil
}

func verifyBridgeApplicationConfigurations(
	config handoffbroker.Config,
	centralSourceIPs []string,
	root string,
) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("Bridge configuration verification root must be absolute and canonical")
	}

	artifacts, err := BuildBridgeApplicationConfigurations(config, centralSourceIPs)
	if err != nil {
		return err
	}

	directory := filepath.Join(root, strings.TrimPrefix(bridgeApplicationConfigDirectory, string(os.PathSeparator)))
	if err := ensureNoSymlinkPath(directory); err != nil {
		return fmt.Errorf("Bridge application configuration directory is unsafe: %w", err)
	}

	directoryMetadata, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect Bridge application configuration directory: %w", err)
	}
	directoryStat, ok := directoryMetadata.Sys().(*syscall.Stat_t)
	if !ok ||
		directoryMetadata.Mode()&os.ModeSymlink != 0 ||
		!directoryMetadata.IsDir() ||
		int(directoryStat.Uid) != 0 ||
		int(directoryStat.Gid) != 0 ||
		directoryMetadata.Mode().Perm() != bridgeApplicationConfigDirectoryMode {
		return errors.New("Bridge application configuration directory has unexpected ownership or permissions")
	}

	for _, artifact := range artifacts {
		destination := filepath.Join(root, strings.TrimPrefix(artifact.Path, string(os.PathSeparator)))
		content, err := readRootOwnedRegularFile(destination, 16*1024)
		if err != nil || !bytes.Equal(content, artifact.Content) {
			return errors.New("installed Bridge application configuration does not match the verified application identity and allowlist")
		}

		metadata, err := os.Lstat(destination)
		if err != nil {
			return errors.New("installed Bridge application configuration metadata is unavailable")
		}
		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok ||
			metadata.Mode()&os.ModeSymlink != 0 ||
			!metadata.Mode().IsRegular() ||
			int(stat.Uid) != 0 ||
			int(stat.Gid) != artifact.GID ||
			metadata.Mode().Perm() != bridgeApplicationConfigFileMode {
			return errors.New("installed Bridge application configuration ownership or permissions are invalid")
		}
	}

	return nil
}

func bridgeApplicationConfigurationTargets(
	config handoffbroker.Config,
	centralSourceIPs []string,
) (map[string]string, error) {
	artifacts, err := BuildBridgeApplicationConfigurations(config, centralSourceIPs)
	if err != nil {
		return nil, err
	}

	targets := map[string]string{
		bridgeApplicationConfigDirectory: "directory",
	}
	for _, artifact := range artifacts {
		targets[artifact.Path] = "file"
	}

	return targets, nil
}
