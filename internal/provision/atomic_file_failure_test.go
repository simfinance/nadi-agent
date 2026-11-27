package provision

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type failingProvisionAtomicFile struct {
	*os.File
	failure string
}

func (file *failingProvisionAtomicFile) Chmod(mode os.FileMode) error {
	if file.failure == "chmod" {
		return errors.New("injected chmod failure")
	}

	return file.File.Chmod(mode)
}

func (file *failingProvisionAtomicFile) Chown(uid int, gid int) error {
	if file.failure == "chown" {
		return errors.New("injected chown failure")
	}

	return file.File.Chown(uid, gid)
}

func (file *failingProvisionAtomicFile) Write(content []byte) (int, error) {
	if file.failure == "write" {
		partialLength := len(content) / 2
		written, _ := file.File.Write(content[:partialLength])

		return written, errors.New("injected write failure")
	}
	if file.failure == "short_write" {
		partialLength := len(content) / 2
		written, err := file.File.Write(content[:partialLength])

		return written, err
	}

	return file.File.Write(content)
}

func (file *failingProvisionAtomicFile) Sync() error {
	if file.failure == "file_sync" {
		return errors.New("injected file sync failure")
	}

	return file.File.Sync()
}

func (file *failingProvisionAtomicFile) Close() error {
	closeErr := file.File.Close()
	if file.failure == "file_close" {
		return errors.New("injected file close failure")
	}

	return closeErr
}

type failingProvisionAtomicDirectory struct {
	*os.File
	failure string
}

func (directory *failingProvisionAtomicDirectory) Sync() error {
	if directory.failure == "directory_sync" {
		return errors.New("injected directory sync failure")
	}

	return directory.File.Sync()
}

func TestWriteOwnedAtomicFileFailureBoundaries(t *testing.T) {
	failureStages := []string{
		"create",
		"chmod",
		"chown",
		"write",
		"short_write",
		"file_sync",
		"file_close",
		"rename",
		"open_directory",
		"directory_sync",
	}

	for _, failureStage := range failureStages {
		t.Run(failureStage, func(t *testing.T) {
			parent := t.TempDir()
			destination := filepath.Join(parent, "managed-file")
			content := []byte("trusted NADI artifact")
			operations := defaultProvisionAtomicFileOperations()

			operations.createTemp = func(directory string, pattern string) (provisionAtomicFile, error) {
				if failureStage == "create" {
					return nil, errors.New("injected temporary-file creation failure")
				}

				file, err := os.CreateTemp(directory, pattern)
				if err != nil {
					return nil, err
				}

				return &failingProvisionAtomicFile{
					File:    file,
					failure: failureStage,
				}, nil
			}
			operations.rename = func(oldPath string, newPath string) error {
				if failureStage == "rename" {
					return errors.New("injected rename failure")
				}

				return os.Rename(oldPath, newPath)
			}
			operations.openDirectory = func(path string) (provisionAtomicDirectory, error) {
				if failureStage == "open_directory" {
					return nil, errors.New("injected directory open failure")
				}

				directory, err := os.Open(path)
				if err != nil {
					return nil, err
				}

				return &failingProvisionAtomicDirectory{
					File:    directory,
					failure: failureStage,
				}, nil
			}

			err := writeOwnedAtomicFileWithOperations(
				destination,
				content,
				0600,
				os.Geteuid(),
				os.Getegid(),
				operations,
			)
			if err == nil {
				t.Fatal("injected filesystem failure must be returned")
			}

			entries, readErr := os.ReadDir(parent)
			if readErr != nil {
				t.Fatalf("read temporary directory: %v", readErr)
			}

			postRenameFailure := failureStage == "open_directory" || failureStage == "directory_sync"
			if postRenameFailure {
				actual, readErr := os.ReadFile(destination)
				if readErr != nil {
					t.Fatalf("destination must remain after rename completed: %v", readErr)
				}
				if string(actual) != string(content) {
					t.Fatal("destination content changed after post-rename failure")
				}
				if len(entries) != 1 || entries[0].Name() != "managed-file" {
					t.Fatalf("temporary file was not cleaned after rename: %v", entries)
				}

				return
			}

			if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("destination must not exist before a successful rename: %v", statErr)
			}
			if len(entries) != 0 {
				t.Fatalf("temporary file was not cleaned after failure: %v", entries)
			}
		})
	}
}


func TestProvisionJournalSaveFailureBoundaries(t *testing.T) {
	failureStages := []string{
		"create",
		"chmod",
		"chown",
		"write",
		"short_write",
		"file_sync",
		"file_close",
		"rename",
		"open_directory",
		"directory_sync",
	}

	for _, failureStage := range failureStages {
		t.Run(failureStage, func(t *testing.T) {
			parent := t.TempDir()
			journalPath := filepath.Join(parent, "provisioning-journal.json")
			store, original, err := newProvisionJournalForOperation(journalPath, "restore_agent")
			if err != nil {
				t.Fatalf("create initial journal: %v", err)
			}

			updated := original
			updated.Phase = "rollback_required"
			updated.UpdatedAt = time.Now().UTC()
			operations := defaultProvisionAtomicFileOperations()

			operations.createTemp = func(directory string, pattern string) (provisionAtomicFile, error) {
				if failureStage == "create" {
					return nil, errors.New("injected temporary-file creation failure")
				}

				file, err := os.CreateTemp(directory, pattern)
				if err != nil {
					return nil, err
				}

				return &failingProvisionAtomicFile{
					File:    file,
					failure: failureStage,
				}, nil
			}
			operations.rename = func(oldPath string, newPath string) error {
				if failureStage == "rename" {
					return errors.New("injected rename failure")
				}

				return os.Rename(oldPath, newPath)
			}
			operations.openDirectory = func(path string) (provisionAtomicDirectory, error) {
				if failureStage == "open_directory" {
					return nil, errors.New("injected directory open failure")
				}

				directory, err := os.Open(path)
				if err != nil {
					return nil, err
				}

				return &failingProvisionAtomicDirectory{
					File:    directory,
					failure: failureStage,
				}, nil
			}

			if err := store.saveWithOperations(updated, operations); err == nil {
				t.Fatal("injected journal filesystem failure must be returned")
			}

			persisted, err := store.Load()
			if err != nil {
				t.Fatalf("load journal after injected failure: %v", err)
			}

			postRenameFailure := failureStage == "open_directory" || failureStage == "directory_sync"
			if postRenameFailure {
				if persisted.Phase != "rollback_required" {
					t.Fatalf("journal must contain the renamed update after post-rename failure, got %q", persisted.Phase)
				}
			} else if persisted.Phase != "in_progress" {
				t.Fatalf("previous journal must remain intact before rename, got %q", persisted.Phase)
			}

			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatalf("read journal directory: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(journalPath) {
				t.Fatalf("temporary journal file was not cleaned: %v", entries)
			}
		})
	}
}
