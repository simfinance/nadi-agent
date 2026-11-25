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

func installBrokerArtifactsJournaled(
	config handoffbroker.Config,
	mappingJSON []byte,
	dropIn string,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if os.Geteuid() != 0 {
		return errors.New("broker artifact installation requires root")
	}

	return installBrokerArtifactsJournaledAt(
		string(os.PathSeparator),
		config,
		mappingJSON,
		dropIn,
		0,
		0,
		store,
		journal,
	)
}

func installBrokerArtifactsJournaledAt(
	root string,
	config handoffbroker.Config,
	mappingJSON []byte,
	dropIn string,
	ownerUID int,
	ownerGID int,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("artifact installation root must be absolute and canonical")
	}
	if store == nil || journal == nil || (journal.Operation != "restore_agent" && journal.Operation != "enroll_agent") {
		return errors.New("identity restore or enrollment journal is required for broker artifact installation")
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

	bridgeRoot := filepath.Join(root, "var", "lib", "nadi-bridge")
	if err := ensureDirectoryTreeJournaled(
		root,
		bridgeRoot,
		bridgeDirectoryMode,
		ownerUID,
		ownerGID,
		store,
		journal,
	); err != nil {
		return fmt.Errorf("prepare Bridge credential root: %w", err)
	}

	for _, application := range config.Applications {
		credentialDirectory := filepath.Join(bridgeRoot, application.ApplicationID)
		if err := ensureDirectoryTreeJournaled(
			root,
			credentialDirectory,
			bridgeDirectoryMode,
			ownerUID,
			ownerGID,
			store,
			journal,
		); err != nil {
			return fmt.Errorf("prepare application credential directory: %w", err)
		}
	}

	mappingPath := filepath.Join(root, "etc", "nadi", "bridge-mappings.json")
	if err := ensureDirectoryTreeJournaled(
		root,
		filepath.Dir(mappingPath),
		nadiConfigDirectoryMode,
		ownerUID,
		ownerGID,
		store,
		journal,
	); err != nil {
		return fmt.Errorf("prepare broker mapping directory: %w", err)
	}
	if err := installImmutableFileJournaled(
		mappingPath,
		mappingJSON,
		brokerMappingFileMode,
		ownerUID,
		ownerGID,
		store,
		journal,
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
	if err := ensureDirectoryTreeJournaled(
		root,
		filepath.Dir(dropInPath),
		systemDirectoryMode,
		ownerUID,
		ownerGID,
		store,
		journal,
	); err != nil {
		return fmt.Errorf("prepare broker systemd drop-in directory: %w", err)
	}
	if err := installImmutableFileJournaled(
		dropInPath,
		[]byte(dropIn),
		brokerDropInFileMode,
		ownerUID,
		ownerGID,
		store,
		journal,
	); err != nil {
		return fmt.Errorf("install broker systemd drop-in: %w", err)
	}

	return nil
}

func expectedEnrollmentJournalTargets(config handoffbroker.Config) map[string]string {
	targets := make(map[string]string)

	addDirectoryTree := func(directory string) {
		for current := directory; current != string(os.PathSeparator); current = filepath.Dir(current) {
			targets[current] = "directory"
		}
	}

	addDirectoryTree("/var/lib/nadi-bridge")
	for _, application := range config.Applications {
		addDirectoryTree(filepath.Join("/var/lib/nadi-bridge", application.ApplicationID))
	}
	addDirectoryTree(filepath.Dir(brokerMappingPath))
	addDirectoryTree(filepath.Dir(brokerDropInPath))

	targets[brokerMappingPath] = "file"
	targets[brokerDropInPath] = "file"
	targets[provisionCompletePath] = "file"

	return targets
}

func verifyBrokerArtifactDirectories(
	config handoffbroker.Config,
	root string,
	ownerUID int,
	ownerGID int,
) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("Bridge verification root must be absolute and canonical")
	}

	directories := []struct {
		path string
		mode os.FileMode
	}{
		{path: filepath.Join(root, "var", "lib", "nadi-bridge"), mode: bridgeDirectoryMode},
		{path: filepath.Join(root, "etc", "nadi"), mode: nadiConfigDirectoryMode},
		{path: filepath.Join(root, "etc", "systemd", "system", "nadi-handoff-broker.service.d"), mode: systemDirectoryMode},
	}
	for _, application := range config.Applications {
		directories = append(directories, struct {
			path string
			mode os.FileMode
		}{
			path: filepath.Join(root, "var", "lib", "nadi-bridge", application.ApplicationID),
			mode: bridgeDirectoryMode,
		})
	}

	for _, directory := range directories {
		if err := ensureNoSymlinkPath(directory.path); err != nil {
			return fmt.Errorf("Bridge directory path %s is unsafe: %w", directory.path, err)
		}
		metadata, err := os.Lstat(directory.path)
		if err != nil {
			return fmt.Errorf("inspect Bridge directory %s: %w", directory.path, err)
		}
		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok ||
			metadata.Mode()&os.ModeSymlink != 0 ||
			!metadata.IsDir() ||
			int(stat.Uid) != ownerUID ||
			int(stat.Gid) != ownerGID ||
			metadata.Mode().Perm() != directory.mode {
			return fmt.Errorf("Bridge directory %s has unexpected type, ownership, or permissions", directory.path)
		}
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

		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != ownerUID || int(stat.Gid) != ownerGID || metadata.Mode().Perm() != mode {
			return errors.New("existing destination ownership or permissions do not match the managed file policy")
		}

		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, content) {
			return errors.New("refusing to overwrite an existing managed file without an approved update operation")
		}

		return nil
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
