package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const provisionJournalPath = "/etc/.nadi-provisioning-journal.json"

var provisionJournalRollbackRoots = []string{
	"/opt/nadi",
	"/etc/nadi",
	"/var/lib/nadi",
	"/var/log/nadi",
	"/run/nadi",
}

func prepareAgentDirectoriesJournaled(
	identity helperRuntimeIdentity,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	directories := []struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}{
		{path: "/opt/nadi", mode: 0755, uid: 0, gid: 0},
		{path: "/opt/nadi/bin", mode: 0755, uid: 0, gid: 0},
		{path: "/etc/nadi", mode: 0750, uid: 0, gid: 0},
		{path: "/etc/nadi/keys", mode: 0750, uid: 0, gid: 0},
		{path: "/var/lib/nadi", mode: 0700, uid: identity.uid, gid: identity.gid},
		{path: "/var/log/nadi", mode: 0750, uid: identity.uid, gid: identity.gid},
		{path: "/run/nadi", mode: 0755, uid: 0, gid: 0},
	}

	for _, directory := range directories {
		if err := ensureDirectoryTreeJournaled(
			string(os.PathSeparator),
			directory.path,
			directory.mode,
			directory.uid,
			directory.gid,
			store,
			journal,
		); err != nil {
			return fmt.Errorf("prepare %s: %w", directory.path, err)
		}
	}

	return nil
}

func ensureDirectoryTreeJournaled(
	root string,
	directory string,
	mode os.FileMode,
	ownerUID int,
	ownerGID int,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if !filepath.IsAbs(root) ||
		filepath.Clean(root) != root ||
		!filepath.IsAbs(directory) ||
		filepath.Clean(directory) != directory ||
		directory == root {
		return errors.New("journaled directory paths must be absolute, canonical, and distinct")
	}

	rootMetadata, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect journaled directory root: %w", err)
	}
	rootStat, ok := rootMetadata.Sys().(*syscall.Stat_t)
	if !ok || rootMetadata.Mode()&os.ModeSymlink != 0 || !rootMetadata.IsDir() ||
		int(rootStat.Uid) != ownerUID || int(rootStat.Gid) != ownerGID ||
		rootMetadata.Mode().Perm()&0022 != 0 {
		return errors.New("journaled directory root ownership or permissions are unsafe")
	}

	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("journaled directory destination is outside the installation root")
	}

	rootUID := int(rootStat.Uid)
	rootGID := int(rootStat.Gid)
	current := root
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("journaled directory destination contains an invalid path segment")
		}

		current = filepath.Join(current, segment)
		isDestination := current == directory
		expectedMode := os.FileMode(0)
		createMode := os.FileMode(0755)
		expectedUID := rootUID
		expectedGID := rootGID
		if isDestination {
			expectedMode = mode
			createMode = mode
			expectedUID = ownerUID
			expectedGID = ownerGID
		}

		metadata, inspectErr := os.Lstat(current)
		if inspectErr == nil {
			if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
				return fmt.Errorf("existing path %s is not a real directory", current)
			}
			stat, ok := metadata.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID ||
				metadata.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("existing directory %s has unsafe ownership or permissions", current)
			}
			if expectedMode != 0 && metadata.Mode().Perm() != expectedMode {
				return fmt.Errorf("existing directory %s has a mode different from the required mode; refusing to modify it", current)
			}
			continue
		}
		if !errors.Is(inspectErr, os.ErrNotExist) {
			return fmt.Errorf("inspect directory %s: %w", current, inspectErr)
		}

		actionIndex, err := store.AddIntent(journal, "directory", current)
		if err != nil {
			return fmt.Errorf("record directory creation intent for %s: %w", current, err)
		}

		if err := os.Mkdir(current, createMode); err != nil {
			if errors.Is(err, os.ErrExist) {
				if markErr := store.MarkSkipped(journal, actionIndex); markErr != nil {
					return fmt.Errorf("record concurrently-created directory %s: %w", current, markErr)
				}
				continue
			}
			return fmt.Errorf("create directory %s: %w", current, err)
		}

		if err := os.Chown(current, expectedUID, expectedGID); err != nil {
			return fmt.Errorf("set directory ownership for %s: %w", current, err)
		}
		if err := os.Chmod(current, createMode); err != nil {
			return fmt.Errorf("set directory permissions for %s: %w", current, err)
		}
		if err := store.MarkApplied(journal, actionIndex); err != nil {
			return fmt.Errorf("record created directory %s: %w", current, err)
		}
	}

	return nil
}

func installImmutableFileJournaled(
	path string,
	content []byte,
	mode os.FileMode,
	uid int,
	gid int,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	if metadata, err := os.Lstat(path); err == nil {
		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
			return errors.New("existing installation destination is not a regular file")
		}
		return installImmutableFile(path, content, mode, uid, gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	actionIndex, err := store.AddIntent(journal, "file", path)
	if err != nil {
		return fmt.Errorf("record file creation intent for %s: %w", path, err)
	}

	if err := installImmutableFile(path, content, mode, uid, gid); err != nil {
		return err
	}
	if err := store.MarkApplied(journal, actionIndex); err != nil {
		return fmt.Errorf("record installed file %s: %w", path, err)
	}

	return nil
}

func installAgentAssetsJournaled(
	artifactPath string,
	expectedDigest string,
	store *provisionJournalStore,
	journal *provisionJournal,
) error {
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return fmt.Errorf("read verified Agent artifact: %w", err)
	}
	if len(artifact) == 0 || len(artifact) > maximumArtifactBytes {
		return errors.New("verified Agent artifact size is invalid")
	}

	digest := sha256SumHex(artifact)
	if digest != expectedDigest {
		return errors.New("Agent artifact changed after signature and checksum verification")
	}

	assets := []struct {
		path    string
		content []byte
		mode    os.FileMode
		uid     int
		gid     int
	}{
		{path: agentBinaryPath, content: artifact, mode: 0755, uid: 0, gid: 0},
		{path: activationPublicKeyPath, content: helperActivationPublicKey, mode: 0644, uid: 0, gid: 0},
		{path: agentUnitPath, content: helperAgentUnit, mode: 0644, uid: 0, gid: 0},
		{path: brokerUnitPath, content: helperBrokerUnit, mode: 0644, uid: 0, gid: 0},
	}

	for _, asset := range assets {
		if err := installImmutableFileJournaled(
			asset.path,
			asset.content,
			asset.mode,
			asset.uid,
			asset.gid,
			store,
			journal,
		); err != nil {
			return fmt.Errorf("install %s: %w", asset.path, err)
		}
	}

	return nil
}

func sha256SumHex(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func removeProvisionJournal(store *provisionJournalStore, phase string) error {
	if store == nil || (phase != "committed" && phase != "rolled_back") {
		return errors.New("only a committed or rolled-back provisioning journal can be removed")
	}

	metadata, err := os.Lstat(store.path)
	if err != nil {
		return err
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok ||
		metadata.Mode()&os.ModeSymlink != 0 ||
		!metadata.Mode().IsRegular() ||
		stat.Uid != store.ownerUID ||
		stat.Gid != store.ownerGID ||
		metadata.Mode().Perm() != 0600 {
		return errors.New("provisioning journal has unsafe metadata; refusing removal")
	}

	if err := os.Remove(store.path); err != nil {
		return fmt.Errorf("remove completed provisioning journal: %w", err)
	}

	directory, err := os.Open(filepath.Dir(store.path))
	if err != nil {
		return err
	}
	defer directory.Close()

	return directory.Sync()
}

func recoverProvisionJournalForInstall(
	releaseVersion string,
	artifactSHA256 string,
	applications []ProvisionApplication,
) (bool, error) {
	metadata, err := os.Lstat(provisionJournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect previous provisioning journal: %w", err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return false, errors.New("previous provisioning journal is unsafe; manual recovery is required")
	}

	store, journal, err := openProvisionJournal(provisionJournalPath)
	if err != nil {
		return false, fmt.Errorf("previous provisioning journal cannot be verified: %w", err)
	}

	switch journal.Phase {
	case "committed":
		inventory, inventoryErr := readProvisionInventory()
		if inventoryErr != nil ||
			inventory.AgentVersion != releaseVersion ||
			inventory.ArtifactSHA256 != artifactSHA256 ||
			!sameApplicationInventory(inventory.Applications, applications) {
			return false, errors.New("committed provisioning journal does not match the installed inventory; manual recovery is required")
		}
		if err := removeProvisionJournal(store, "committed"); err != nil {
			return false, err
		}
		return true, nil
	case "rolled_back":
		if err := removeProvisionJournal(store, "rolled_back"); err != nil {
			return false, err
		}
		return false, nil
	case "in_progress", "rollback_required":
		if err := store.Rollback(&journal, provisionJournalRollbackRoots); err != nil {
			return false, err
		}
		if err := removeProvisionJournal(store, "rolled_back"); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, errors.New("previous provisioning journal has an unsupported phase")
	}
}
