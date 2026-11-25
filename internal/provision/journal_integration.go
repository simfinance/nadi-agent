package provision

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	"/var/lib/nadi-bridge",
	"/etc/systemd",
}

const provisionLockPath = "/etc/.nadi-provisioning.lock"

func acquireProvisionLock() (func(), error) {
	return acquireProvisionLockAt(provisionLockPath)
}

func acquireProvisionLockAt(path string) (func(), error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("provisioning lock path must be absolute and canonical")
	}

	ownerUID := uint32(os.Geteuid())
	ownerGID := uint32(os.Getegid())
	if err := validateProvisionJournalParent(path, ownerUID, ownerGID); err != nil {
		return nil, err
	}

	descriptor, err := syscall.Open(
		path,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("open provisioning lock: %w", err)
	}

	metadata := &syscall.Stat_t{}
	if err := syscall.Fstat(descriptor, metadata); err != nil {
		syscall.Close(descriptor)
		return nil, fmt.Errorf("inspect provisioning lock: %w", err)
	}
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		metadata.Uid != ownerUID ||
		metadata.Gid != ownerGID ||
		metadata.Mode&0777 != 0600 {
		syscall.Close(descriptor)
		return nil, errors.New("provisioning lock ownership or permissions are unsafe")
	}

	if err := syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		syscall.Close(descriptor)
		return nil, errors.New("another NADI provisioning operation is already running")
	}

	unlock := func() {
		_ = syscall.Flock(descriptor, syscall.LOCK_UN)
		_ = syscall.Close(descriptor)
	}

	return unlock, nil
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
		rootStat.Uid != uint32(os.Geteuid()) || rootStat.Gid != uint32(os.Getegid()) ||
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
				return fmt.Errorf("directory %s appeared during provisioning; refusing to trust a concurrent resource", current)
			}
			return fmt.Errorf("create directory %s: %w", current, err)
		}

		if expectedUID != os.Geteuid() || expectedGID != os.Getegid() {
			if err := os.Chown(current, expectedUID, expectedGID); err != nil {
				return fmt.Errorf("set directory ownership for %s: %w", current, err)
			}
		}
		if err := os.Chmod(current, createMode); err != nil {
			return fmt.Errorf("set directory permissions for %s: %w", current, err)
		}
		if err := syncProvisionDirectory(current); err != nil {
			return fmt.Errorf("sync created directory %s: %w", current, err)
		}
		if err := syncProvisionDirectory(filepath.Dir(current)); err != nil {
			return fmt.Errorf("sync parent directory for %s: %w", current, err)
		}
		if err := store.MarkApplied(journal, actionIndex); err != nil {
			return fmt.Errorf("record created directory %s: %w", current, err)
		}
	}

	return nil
}

func syncProvisionDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()

	return directory.Sync()
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
	if err := ensureNoSymlinkPath(filepath.Dir(path)); err != nil {
		return fmt.Errorf("installation destination parent is unsafe: %w", err)
	}

	if metadata, err := os.Lstat(path); err == nil {
		if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
			return errors.New("existing installation destination is not a regular file")
		}

		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok ||
			int(stat.Uid) != uid ||
			int(stat.Gid) != gid ||
			metadata.Mode().Perm() != mode ||
			metadata.Size() != int64(len(content)) {
			return errors.New("existing installation destination does not match the immutable file policy")
		}

		descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return fmt.Errorf("open existing immutable installation file: %w", err)
		}
		file := os.NewFile(uintptr(descriptor), path)
		defer file.Close()

		openedMetadata, err := file.Stat()
		if err != nil {
			return fmt.Errorf("inspect existing immutable installation file: %w", err)
		}
		openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
		if !ok ||
			openedStat.Dev != stat.Dev ||
			openedStat.Ino != stat.Ino ||
			openedStat.Uid != stat.Uid ||
			openedStat.Gid != stat.Gid ||
			!openedMetadata.Mode().IsRegular() ||
			openedMetadata.Mode().Perm() != mode ||
			openedMetadata.Size() != int64(len(content)) {
			return errors.New("existing immutable installation file changed during inspection")
		}

		existing, err := io.ReadAll(io.LimitReader(file, int64(len(content))+1))
		if err != nil {
			return fmt.Errorf("read existing immutable installation file: %w", err)
		}
		if !bytes.Equal(existing, content) {
			return errors.New("refusing to replace an existing immutable installation file")
		}

		return nil
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

	persistedJournal, err := store.Load()
	if err != nil {
		return fmt.Errorf("verify provisioning journal before removal: %w", err)
	}
	if persistedJournal.Phase != phase {
		return errors.New("persisted provisioning journal phase does not permit removal")
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

func verifyEnrollmentJournalActions(
	journal *provisionJournal,
	expectedTargets map[string]string,
) error {
	if journal == nil || journal.Operation != "enroll_agent" {
		return errors.New("enrollment journal is required")
	}

	for index, action := range journal.Actions {
		expectedKind, exists := expectedTargets[action.Target]
		if !exists || expectedKind != action.Kind {
			return fmt.Errorf("enrollment journal action %d targets an unexpected resource", index)
		}

		switch action.State {
		case "applied":
			if action.Fingerprint == nil {
				return fmt.Errorf("enrollment journal action %d has no persisted fingerprint", index)
			}
			current, err := fingerprintProvisionResource(action.Kind, action.Target)
			if err != nil {
				return fmt.Errorf("inspect enrollment journal action %d: %w", index, err)
			}
			if current != *action.Fingerprint {
				return fmt.Errorf("enrollment journal action %d no longer matches its transaction fingerprint", index)
			}
		case "rolled_back":
			if action.Fingerprint != nil {
				return fmt.Errorf("enrollment journal action %d has an invalid skipped fingerprint", index)
			}
		default:
			return fmt.Errorf("enrollment journal action %d is not in a recoverable state", index)
		}
	}

	return nil
}

func reconcileEnrollmentJournalActions(
	store *provisionJournalStore,
	journal *provisionJournal,
	expectedTargets map[string]string,
) error {
	if store == nil || journal == nil || journal.Operation != "enroll_agent" {
		return errors.New("enrollment journal store and journal are required")
	}

	for index := range journal.Actions {
		action := &journal.Actions[index]
		expectedKind, exists := expectedTargets[action.Target]
		if !exists || expectedKind != action.Kind {
			return fmt.Errorf("enrollment journal action %d targets an unexpected resource", index)
		}
		if action.State == "intent" {
			if err := store.MarkSkipped(journal, index); err != nil {
				return fmt.Errorf("preserve ambiguous enrollment intent %d: %w", index, err)
			}
		}
	}

	return verifyEnrollmentJournalActions(journal, expectedTargets)
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

	if journal.Operation == "enroll_agent" {
		inventory, inventoryErr := readProvisionInventory()
		if inventoryErr != nil ||
			inventory.AgentVersion != releaseVersion ||
			inventory.ArtifactSHA256 != artifactSHA256 ||
			!sameApplicationInventory(inventory.Applications, applications) {
			return false, errors.New("interrupted enrollment journal does not match the requested installed inventory; preserve Agent identity and reconcile manually")
		}
		if err := recoverEnrollmentJournal(inventory); err != nil {
			return false, fmt.Errorf("recover interrupted enrollment before installation: %w", err)
		}
		return false, nil
	}

	switch journal.Phase {
	case "committed":
		if journal.Operation == "enroll_agent" {
			return false, errors.New("a committed enrollment journal requires identity verification before it can be cleared")
		}
		inventory, inventoryErr := readProvisionInventory()
		if inventoryErr != nil ||
			inventory.AgentVersion != releaseVersion ||
			inventory.ArtifactSHA256 != artifactSHA256 ||
			!sameApplicationInventory(inventory.Applications, applications) {
			return false, errors.New("committed provisioning journal does not match the installed inventory; manual recovery is required")
		}
		if journal.Operation == "restore_agent" {
			completion, completionErr := readProvisionCompletion()
			if completionErr != nil ||
				completion.AgentVersion != releaseVersion ||
				completion.ApplicationCount != len(applications) ||
				completion.EnrollmentStatus != "registered" {
				return false, errors.New("committed identity restore journal has no matching enrollment completion record")
			}
			if err := removeProvisionJournal(store, "committed"); err != nil {
				return false, err
			}
			return false, nil
		}
		if journal.Operation != "install_agent" {
			return false, errors.New("committed provisioning journal has an unsupported operation")
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
		if journal.Operation == "enroll_agent" {
			return false, errors.New("an interrupted enrollment transaction may already be registered in Central; preserve Agent identity and reconcile before recovery")
		}
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
