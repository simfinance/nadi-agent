package provision

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	provisionJournalSchemaVersion = 1
	provisionJournalMaximumBytes  = 1 << 20
)

type provisionJournal struct {
	ProtocolVersion int                      `json:"protocol_version"`
	TransactionID   string                   `json:"transaction_id"`
	Operation       string                   `json:"operation"`
	Phase           string                   `json:"phase"`
	CreatedAt       time.Time                `json:"created_at"`
	UpdatedAt       time.Time                `json:"updated_at"`
	Actions         []provisionJournalAction `json:"actions"`
}

type provisionJournalAction struct {
	Kind        string                       `json:"kind"`
	Target      string                       `json:"target"`
	State       string                       `json:"state"`
	Fingerprint *provisionJournalFingerprint `json:"fingerprint,omitempty"`
}

type provisionJournalFingerprint struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
}

type provisionJournalStore struct {
	path     string
	ownerUID uint32
	ownerGID uint32
}

func newProvisionJournal(path string) (*provisionJournalStore, provisionJournal, error) {
	return newProvisionJournalForOperation(path, "install_agent")
}

func newProvisionJournalForOperation(path string, operation string) (*provisionJournalStore, provisionJournal, error) {
	if operation != "install_agent" && operation != "restore_agent" && operation != "enroll_agent" {
		return nil, provisionJournal{}, errors.New("unsupported provisioning journal operation")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, provisionJournal{}, errors.New("provisioning journal path must be absolute and canonical")
	}

	metadata, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, provisionJournal{}, fmt.Errorf("inspect provisioning journal directory: %w", err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.IsDir() {
		return nil, provisionJournal{}, errors.New("provisioning journal parent must be a real directory")
	}
	if err := validateProvisionJournalParent(path, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return nil, provisionJournal{}, err
	}

	if _, err := os.Lstat(path); err == nil {
		return nil, provisionJournal{}, errors.New("a provisioning journal already exists; recovery is required")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, provisionJournal{}, fmt.Errorf("inspect existing provisioning journal: %w", err)
	}

	transactionIDBytes := make([]byte, 16)
	if _, err := rand.Read(transactionIDBytes); err != nil {
		return nil, provisionJournal{}, fmt.Errorf("generate provisioning transaction ID: %w", err)
	}

	now := time.Now().UTC()
	journal := provisionJournal{
		ProtocolVersion: provisionJournalSchemaVersion,
		TransactionID:   hex.EncodeToString(transactionIDBytes),
		Operation:       operation,
		Phase:           "in_progress",
		CreatedAt:       now,
		UpdatedAt:       now,
		Actions:         make([]provisionJournalAction, 0),
	}
	store := &provisionJournalStore{
		path:     path,
		ownerUID: uint32(os.Geteuid()),
		ownerGID: uint32(os.Getegid()),
	}

	if err := store.Save(journal); err != nil {
		return nil, provisionJournal{}, err
	}

	return store, journal, nil
}

func openProvisionJournal(path string) (*provisionJournalStore, provisionJournal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, provisionJournal{}, errors.New("provisioning journal path must be absolute and canonical")
	}

	store := &provisionJournalStore{
		path:     path,
		ownerUID: uint32(os.Geteuid()),
		ownerGID: uint32(os.Getegid()),
	}
	if err := validateProvisionJournalParent(path, store.ownerUID, store.ownerGID); err != nil {
		return nil, provisionJournal{}, err
	}
	journal, err := store.Load()
	if err != nil {
		return nil, provisionJournal{}, err
	}

	return store, journal, nil
}

func (s *provisionJournalStore) Load() (provisionJournal, error) {
	pathMetadata, err := os.Lstat(s.path)
	if err != nil {
		return provisionJournal{}, fmt.Errorf("inspect provisioning journal: %w", err)
	}

	pathStat, ok := pathMetadata.Sys().(*syscall.Stat_t)
	if !ok ||
		pathMetadata.Mode()&os.ModeSymlink != 0 ||
		!pathMetadata.Mode().IsRegular() ||
		pathStat.Uid != s.ownerUID ||
		pathStat.Gid != s.ownerGID ||
		pathMetadata.Mode().Perm() != 0600 ||
		pathMetadata.Size() < 1 ||
		pathMetadata.Size() > provisionJournalMaximumBytes {
		return provisionJournal{}, errors.New("provisioning journal ownership, permissions, or size are unsafe")
	}

	file, err := os.Open(s.path)
	if err != nil {
		return provisionJournal{}, fmt.Errorf("open provisioning journal: %w", err)
	}
	defer file.Close()

	openedMetadata, err := file.Stat()
	if err != nil {
		return provisionJournal{}, fmt.Errorf("inspect opened provisioning journal: %w", err)
	}
	openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
	if !ok ||
		openedStat.Dev != pathStat.Dev ||
		openedStat.Ino != pathStat.Ino ||
		openedStat.Uid != s.ownerUID ||
		openedStat.Gid != s.ownerGID ||
		!openedMetadata.Mode().IsRegular() ||
		openedMetadata.Mode().Perm() != 0600 {
		return provisionJournal{}, errors.New("provisioning journal changed during access")
	}

	content, err := io.ReadAll(io.LimitReader(file, provisionJournalMaximumBytes+1))
	if err != nil {
		return provisionJournal{}, fmt.Errorf("read provisioning journal: %w", err)
	}
	if len(content) == 0 || len(content) > provisionJournalMaximumBytes {
		return provisionJournal{}, errors.New("provisioning journal is empty or exceeds the size limit")
	}
	if err := rejectDuplicateJSONKeys(content); err != nil {
		return provisionJournal{}, errors.New("provisioning journal contains duplicate JSON keys")
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var journal provisionJournal
	if err := decoder.Decode(&journal); err != nil {
		return provisionJournal{}, errors.New("provisioning journal JSON is invalid")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return provisionJournal{}, errors.New("provisioning journal contains trailing data")
	}
	if err := validateProvisionJournal(journal); err != nil {
		return provisionJournal{}, err
	}

	return journal, nil
}

func validateProvisionJournalParent(path string, ownerUID uint32, ownerGID uint32) error {
	parent := filepath.Dir(path)
	if err := ensureNoSymlinkPath(parent); err != nil {
		return fmt.Errorf("provisioning journal parent path is unsafe: %w", err)
	}

	metadata, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect provisioning journal parent: %w", err)
	}
	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != ownerUID || stat.Gid != ownerGID || metadata.Mode().Perm()&0022 != 0 {
		return errors.New("provisioning journal parent ownership or permissions are unsafe")
	}

	return nil
}

func (s *provisionJournalStore) Save(journal provisionJournal) error {
	if err := validateProvisionJournal(journal); err != nil {
		return err
	}
	if err := validateProvisionJournalParent(s.path, s.ownerUID, s.ownerGID); err != nil {
		return err
	}

	if metadata, err := os.Lstat(s.path); err == nil {
		stat, ok := metadata.Sys().(*syscall.Stat_t)
		if !ok ||
			metadata.Mode()&os.ModeSymlink != 0 ||
			!metadata.Mode().IsRegular() ||
			stat.Uid != s.ownerUID ||
			stat.Gid != s.ownerGID ||
			metadata.Mode().Perm() != 0600 {
			return errors.New("refusing to replace an unsafe provisioning journal")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect provisioning journal before update: %w", err)
	}

	content, err := json.Marshal(journal)
	if err != nil {
		return fmt.Errorf("encode provisioning journal: %w", err)
	}
	if len(content) == 0 || len(content) > provisionJournalMaximumBytes {
		return errors.New("provisioning journal exceeds the size limit")
	}

	directory := filepath.Dir(s.path)
	temporary, err := os.CreateTemp(directory, ".nadi-provision-journal-*")
	if err != nil {
		return fmt.Errorf("create temporary provisioning journal: %w", err)
	}

	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = os.Remove(temporaryPath)
	}

	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		cleanup()
		return fmt.Errorf("set provisioning journal permissions: %w", err)
	}
	if err := temporary.Chown(int(s.ownerUID), int(s.ownerGID)); err != nil {
		temporary.Close()
		cleanup()
		return fmt.Errorf("set provisioning journal ownership: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		cleanup()
		return fmt.Errorf("write provisioning journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		cleanup()
		return fmt.Errorf("sync provisioning journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close provisioning journal: %w", err)
	}

	if err := os.Rename(temporaryPath, s.path); err != nil {
		cleanup()
		return fmt.Errorf("atomically replace provisioning journal: %w", err)
	}

	parent, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open provisioning journal directory for sync: %w", err)
	}
	defer parent.Close()

	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync provisioning journal directory: %w", err)
	}

	return nil
}

func validateProvisionJournal(journal provisionJournal) error {
	if journal.ProtocolVersion != provisionJournalSchemaVersion ||
		len(journal.TransactionID) != 32 ||
		(journal.Operation != "install_agent" && journal.Operation != "restore_agent" && journal.Operation != "enroll_agent") ||
		(journal.Phase != "in_progress" &&
			journal.Phase != "rollback_required" &&
			journal.Phase != "rolled_back" &&
			journal.Phase != "committed") ||
		journal.CreatedAt.IsZero() ||
		journal.UpdatedAt.IsZero() {
		return errors.New("provisioning journal header is invalid")
	}

	for _, action := range journal.Actions {
		validTarget := filepath.IsAbs(action.Target) && filepath.Clean(action.Target) == action.Target
		if action.Kind == "account" {
			validTarget = action.Target == "nadi-agent"
		}
		if (action.Kind != "file" && action.Kind != "directory" && action.Kind != "account") ||
			!validTarget ||
			(action.State != "intent" && action.State != "applied" && action.State != "retained" && action.State != "rolled_back") {
			return errors.New("provisioning journal contains an invalid action")
		}

		if action.State == "applied" {
			if action.Fingerprint == nil || action.Kind == "account" {
				return errors.New("applied provisioning journal action has no valid resource fingerprint")
			}
			if action.Kind == "file" && len(action.Fingerprint.SHA256) != 64 {
				return errors.New("provisioning journal file fingerprint is incomplete")
			}
			if action.Kind == "directory" && action.Fingerprint.SHA256 != "" {
				return errors.New("provisioning journal directory fingerprint is invalid")
			}
		} else if action.Fingerprint != nil {
			return errors.New("unapplied provisioning journal action must not have a fingerprint")
		}
		if action.State == "retained" && action.Kind != "account" {
			return errors.New("only the fixed service account may be retained by this journal version")
		}
	}

	return nil
}

func (s *provisionJournalStore) AddIntent(journal *provisionJournal, kind string, target string) (int, error) {
	if journal == nil {
		return -1, errors.New("provisioning journal is required")
	}
	validTarget := filepath.IsAbs(target) && filepath.Clean(target) == target
	if kind == "account" {
		validTarget = target == "nadi-agent"
	}
	if (kind != "file" && kind != "directory" && kind != "account") || !validTarget {
		return -1, errors.New("provisioning journal action target is invalid")
	}

	journal.Actions = append(journal.Actions, provisionJournalAction{
		Kind:   kind,
		Target: target,
		State:  "intent",
	})
	journal.UpdatedAt = time.Now().UTC()

	index := len(journal.Actions) - 1
	if err := s.Save(*journal); err != nil {
		journal.Actions = journal.Actions[:index]
		return -1, err
	}

	return index, nil
}

func (s *provisionJournalStore) MarkSkipped(journal *provisionJournal, index int) error {
	if journal == nil || index < 0 || index >= len(journal.Actions) {
		return errors.New("provisioning journal action index is invalid")
	}
	action := &journal.Actions[index]
	if action.State != "intent" || action.Fingerprint != nil {
		return errors.New("only an unapplied provisioning action can be skipped")
	}

	action.State = "rolled_back"
	journal.UpdatedAt = time.Now().UTC()
	if err := s.Save(*journal); err != nil {
		action.State = "intent"
		return err
	}

	return nil
}

func (s *provisionJournalStore) MarkRetained(journal *provisionJournal, index int) error {
	if journal == nil || index < 0 || index >= len(journal.Actions) {
		return errors.New("provisioning journal action index is invalid")
	}
	action := &journal.Actions[index]
	if action.Kind != "account" || action.State != "intent" {
		return errors.New("only an intended fixed service account action can be retained")
	}

	action.State = "retained"
	journal.UpdatedAt = time.Now().UTC()
	if err := s.Save(*journal); err != nil {
		action.State = "intent"
		return err
	}

	return nil
}

func (s *provisionJournalStore) MarkApplied(journal *provisionJournal, index int) error {
	if journal == nil || index < 0 || index >= len(journal.Actions) {
		return errors.New("provisioning journal action index is invalid")
	}

	action := &journal.Actions[index]
	if action.State != "intent" || (action.Kind != "file" && action.Kind != "directory") {
		return errors.New("only an intended file or directory action can be marked applied")
	}
	fingerprint, err := fingerprintProvisionResource(action.Kind, action.Target)
	if err != nil {
		return fmt.Errorf("fingerprint provisioned %s %s: %w", action.Kind, action.Target, err)
	}

	action.Fingerprint = &fingerprint
	action.State = "applied"
	journal.UpdatedAt = time.Now().UTC()

	if err := s.Save(*journal); err != nil {
		action.Fingerprint = nil
		action.State = "intent"
		return err
	}

	return nil
}

func fingerprintProvisionResource(kind string, path string) (provisionJournalFingerprint, error) {
	if err := ensureNoSymlinkPath(filepath.Dir(path)); err != nil {
		return provisionJournalFingerprint{}, fmt.Errorf("journal resource parent path is unsafe: %w", err)
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		return provisionJournalFingerprint{}, err
	}
	if metadata.Mode()&os.ModeSymlink != 0 {
		return provisionJournalFingerprint{}, errors.New("symlink resources cannot be journaled")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok {
		return provisionJournalFingerprint{}, errors.New("resource metadata is unavailable")
	}

	fingerprint := provisionJournalFingerprint{
		Device: uint64(stat.Dev),
		Inode:  uint64(stat.Ino),
		UID:    stat.Uid,
		GID:    stat.Gid,
		Mode:   uint32(metadata.Mode().Perm()),
		Size:   metadata.Size(),
	}

	switch kind {
	case "file":
		if !metadata.Mode().IsRegular() || metadata.Size() < 0 || metadata.Size() > maximumArtifactBytes {
			return provisionJournalFingerprint{}, errors.New("journaled file is not regular or exceeds the size limit")
		}

		file, err := os.Open(path)
		if err != nil {
			return provisionJournalFingerprint{}, err
		}
		defer file.Close()

		openedMetadata, err := file.Stat()
		if err != nil {
			return provisionJournalFingerprint{}, err
		}
		openedStat, ok := openedMetadata.Sys().(*syscall.Stat_t)
		if !ok ||
			openedStat.Dev != stat.Dev ||
			openedStat.Ino != stat.Ino ||
			openedStat.Uid != stat.Uid ||
			openedStat.Gid != stat.Gid ||
			!openedMetadata.Mode().IsRegular() {
			return provisionJournalFingerprint{}, errors.New("journaled file changed during fingerprint inspection")
		}

		content, err := io.ReadAll(io.LimitReader(file, maximumArtifactBytes+1))
		if err != nil {
			return provisionJournalFingerprint{}, err
		}
		if int64(len(content)) != openedMetadata.Size() || int64(len(content)) > maximumArtifactBytes {
			return provisionJournalFingerprint{}, errors.New("journaled file changed size during fingerprint inspection")
		}

		finalMetadata, err := file.Stat()
		if err != nil {
			return provisionJournalFingerprint{}, err
		}
		finalStat, ok := finalMetadata.Sys().(*syscall.Stat_t)
		if !ok ||
			finalStat.Dev != openedStat.Dev ||
			finalStat.Ino != openedStat.Ino ||
			finalMetadata.Size() != openedMetadata.Size() ||
			!finalMetadata.ModTime().Equal(openedMetadata.ModTime()) {
			return provisionJournalFingerprint{}, errors.New("journaled file changed while its fingerprint was calculated")
		}

		digest := sha256.Sum256(content)
		fingerprint.SHA256 = hex.EncodeToString(digest[:])
	case "directory":
		if !metadata.IsDir() {
			return provisionJournalFingerprint{}, errors.New("journaled directory is not a directory")
		}
	default:
		return provisionJournalFingerprint{}, errors.New("unsupported journal resource kind")
	}

	return fingerprint, nil
}

func (s *provisionJournalStore) Rollback(journal *provisionJournal, allowedRoots []string) error {
	if journal == nil {
		return errors.New("provisioning journal is required")
	}
	if journal.Operation == "enroll_agent" {
		return errors.New("enrollment journal cannot be rolled back because Central may already have accepted the Agent identity")
	}
	if journal.Phase != "in_progress" && journal.Phase != "rollback_required" {
		return errors.New("provisioning journal is not in a rollback-eligible phase")
	}
	journal.Phase = "rollback_required"
	journal.UpdatedAt = time.Now().UTC()
	if err := s.Save(*journal); err != nil {
		return fmt.Errorf("persist rollback phase: %w", err)
	}

	for index := len(journal.Actions) - 1; index >= 0; index-- {
		action := &journal.Actions[index]
		if action.State == "rolled_back" || action.State == "retained" {
			continue
		}
		if action.State == "intent" && action.Kind != "account" {
			if _, err := os.Lstat(action.Target); errors.Is(err, os.ErrNotExist) {
				action.State = "rolled_back"
				journal.UpdatedAt = time.Now().UTC()
				if err := s.Save(*journal); err != nil {
					return fmt.Errorf("persist absent intent rollback at action %d: %w", index, err)
				}
				continue
			}
		}
		if action.State != "applied" || action.Fingerprint == nil {
			return fmt.Errorf("recovery required: action %d has no verified post-operation fingerprint", index)
		}
		if !provisionJournalTargetAllowed(action.Target, allowedRoots) {
			return fmt.Errorf("recovery required: action %d target is outside the rollback allowlist", index)
		}

		if err := removeProvisionJournalResource(*action); err != nil {
			return fmt.Errorf("recovery required: rollback action %d failed: %w", index, err)
		}

		action.State = "rolled_back"
		action.Fingerprint = nil
		journal.UpdatedAt = time.Now().UTC()
		if err := s.Save(*journal); err != nil {
			return fmt.Errorf("resource rollback completed but journal update failed at action %d: %w", index, err)
		}
	}

	journal.Phase = "rolled_back"
	journal.UpdatedAt = time.Now().UTC()
	if err := s.Save(*journal); err != nil {
		return fmt.Errorf("persist completed rollback: %w", err)
	}

	return nil
}

func provisionJournalTargetAllowed(target string, allowedRoots []string) bool {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return false
	}

	for _, root := range allowedRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			continue
		}
		relative, err := filepath.Rel(root, target)
		if err == nil && relative != ".." &&
			!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}

	return false
}

func removeProvisionJournalResource(action provisionJournalAction) error {
	current, err := fingerprintProvisionResource(action.Kind, action.Target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current != *action.Fingerprint {
		return errors.New("resource no longer matches the transaction fingerprint; refusing deletion")
	}

	if action.Kind == "directory" {
		return os.Remove(action.Target)
	}

	return os.Remove(action.Target)
}

func (s *provisionJournalStore) Commit(journal *provisionJournal) error {
	if journal == nil {
		return errors.New("provisioning journal is required")
	}
	if journal.Phase != "in_progress" {
		return errors.New("only an in-progress provisioning journal can be committed")
	}
	for _, action := range journal.Actions {
		if action.State != "applied" && action.State != "retained" && action.State != "rolled_back" {
			return errors.New("cannot commit a provisioning journal with incomplete actions")
		}
	}

	journal.Phase = "committed"
	journal.UpdatedAt = time.Now().UTC()

	return s.Save(*journal)
}
