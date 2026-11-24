package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"nadi-agent/internal/handoffbroker"
)

const (
	brokerMappingFileMode   os.FileMode = 0600
	brokerDropInFileMode    os.FileMode = 0644
	bridgeDirectoryMode     os.FileMode = 0711
	systemDirectoryMode     os.FileMode = 0755
	nadiConfigDirectoryMode os.FileMode = 0750
)

// InstallBrokerArtifacts installs only the fixed broker mapping, per-application
// credential directories, and generated systemd drop-in. It never starts or
// reloads a service.
func InstallBrokerArtifacts(
	config handoffbroker.Config,
	mappingJSON []byte,
	dropIn string,
) error {
	if os.Geteuid() != 0 {
		return errors.New("broker artifact installation requires root")
	}

	return installBrokerArtifactsAt(
		string(os.PathSeparator),
		config,
		mappingJSON,
		dropIn,
		0,
		0,
	)
}

func installBrokerArtifactsAt(
	root string,
	config handoffbroker.Config,
	mappingJSON []byte,
	dropIn string,
	ownerUID int,
	ownerGID int,
) error {
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("artifact installation root must be absolute")
	}

	expectedMapping, err := encodeBrokerMapping(config)
	if err != nil {
		return err
	}

	if !bytes.Equal(mappingJSON, expectedMapping) {
		return errors.New("broker mapping bytes do not match the validated configuration")
	}

	expectedDropIn, err := BuildBrokerDropIn(config)
	if err != nil {
		return err
	}

	if dropIn != expectedDropIn {
		return errors.New("systemd drop-in does not match the validated broker configuration")
	}

	if err := ensureOwnedDirectory(root, systemDirectoryMode, ownerUID, ownerGID); err != nil {
		return fmt.Errorf("validate artifact installation root: %w", err)
	}

	bridgeRoot := filepath.Join(root, "var", "lib", "nadi-bridge")
	if err := ensureDirectoryTree(
		root,
		bridgeRoot,
		bridgeDirectoryMode,
		ownerUID,
		ownerGID,
	); err != nil {
		return fmt.Errorf("prepare Bridge credential root: %w", err)
	}

	for _, application := range config.Applications {
		credentialDirectory := filepath.Join(bridgeRoot, application.ApplicationID)
		if err := ensureDirectoryTree(
			root,
			credentialDirectory,
			bridgeDirectoryMode,
			ownerUID,
			ownerGID,
		); err != nil {
			return fmt.Errorf("prepare application credential directory: %w", err)
		}
	}

	mappingPath := filepath.Join(root, "etc", "nadi", "bridge-mappings.json")
	if err := ensureDirectoryTree(
		root,
		filepath.Dir(mappingPath),
		nadiConfigDirectoryMode,
		ownerUID,
		ownerGID,
	); err != nil {
		return fmt.Errorf("prepare broker mapping directory: %w", err)
	}

	if err := writeOwnedAtomicFile(
		mappingPath,
		mappingJSON,
		brokerMappingFileMode,
		ownerUID,
		ownerGID,
	); err != nil {
		return fmt.Errorf("install broker mapping: %w", err)
	}

	dropInPath := filepath.Join(
		root,
		"etc",
		"systemd",
		"system",
		"nadi-handoff-broker.service.d",
		"bridge-credentials.conf",
	)
	if err := ensureDirectoryTree(
		root,
		filepath.Dir(dropInPath),
		systemDirectoryMode,
		ownerUID,
		ownerGID,
	); err != nil {
		return fmt.Errorf("prepare broker systemd drop-in directory: %w", err)
	}

	if err := writeOwnedAtomicFile(
		dropInPath,
		[]byte(dropIn),
		brokerDropInFileMode,
		ownerUID,
		ownerGID,
	); err != nil {
		return fmt.Errorf("install broker systemd drop-in: %w", err)
	}

	return nil
}

func encodeBrokerMapping(config handoffbroker.Config) ([]byte, error) {
	if _, err := handoffbroker.NewServer(
		"/run/nadi/credential-handoff.sock",
		config,
	); err != nil {
		return nil, fmt.Errorf("broker mapping is invalid: %w", err)
	}

	content, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("encode broker mapping: %w", err)
	}

	return append(content, '\n'), nil
}

func ensureDirectoryTree(
	root string,
	directory string,
	mode os.FileMode,
	ownerUID int,
	ownerGID int,
) error {
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("directory destination must be beneath the installation root")
	}

	current := root
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("directory destination contains an invalid path segment")
		}

		current = filepath.Join(current, segment)
		isDestination := current == directory
		createMode := systemDirectoryMode
		validationMode := os.FileMode(0)
		if isDestination {
			createMode = mode
			validationMode = mode
		}

		if err := os.Mkdir(current, createMode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create directory %s: %w", current, err)
		}

		if err := ensureOwnedDirectory(current, validationMode, ownerUID, ownerGID); err != nil {
			return fmt.Errorf("validate directory %s: %w", current, err)
		}
	}

	return nil
}

func ensureOwnedDirectory(
	path string,
	mode os.FileMode,
	ownerUID int,
	ownerGID int,
) error {
	metadata, err := os.Lstat(path)
	if err != nil {
		return err
	}

	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
		return errors.New("directory must be a real directory, not a symlink")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != ownerUID || int(stat.Gid) != ownerGID {
		return errors.New("directory ownership does not match the required owner")
	}

	if metadata.Mode().Perm()&0022 != 0 {
		return errors.New("directory must not be group- or other-writable")
	}

	if mode != 0 && metadata.Mode().Perm() != mode {
		if err := os.Chmod(path, mode); err != nil {
			return fmt.Errorf("set directory permissions: %w", err)
		}
	}

	return nil
}

func writeOwnedAtomicFile(
	path string,
	content []byte,
	mode os.FileMode,
	ownerUID int,
	ownerGID int,
) error {
	parent := filepath.Dir(path)
	if err := ensureOwnedDirectory(parent, 0, ownerUID, ownerGID); err != nil {
		return fmt.Errorf("destination parent is unsafe: %w", err)
	}

	if metadata, err := os.Lstat(path); err == nil {
		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
			return errors.New("existing destination must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	temporary, err := os.CreateTemp(parent, ".nadi-provision-*.tmp")
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}

	if err := temporary.Chown(ownerUID, ownerGID); err != nil {
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
