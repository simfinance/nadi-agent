package logdedupe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const MaximumFingerprints = 10000

type Store struct {
	directory string
	mu        sync.Mutex
}

func Open(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("log deduplication directory must not be empty")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create log deduplication directory: %w", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("secure log deduplication directory: %w", err)
	}

	return &Store{directory: directory}, nil
}

func (s *Store) Unseen(scope string, fingerprints []string) ([]string, error) {
	if strings.TrimSpace(scope) == "" {
		return nil, errors.New("log deduplication scope must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	known, err := s.load(scope)
	if err != nil {
		return nil, err
	}

	unseen := make([]string, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if strings.TrimSpace(fingerprint) == "" {
			return nil, errors.New("log fingerprint must not be empty")
		}
		if _, exists := known[fingerprint]; !exists {
			unseen = append(unseen, fingerprint)
		}
	}

	return unseen, nil
}

func (s *Store) Commit(scope string, fingerprints []string) error {
	if strings.TrimSpace(scope) == "" {
		return errors.New("log deduplication scope must not be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, err := s.loadOrdered(scope)
	if err != nil {
		return err
	}

	known := make(map[string]struct{}, len(current)+len(fingerprints))
	for _, fingerprint := range current {
		known[fingerprint] = struct{}{}
	}

	for _, fingerprint := range fingerprints {
		if strings.TrimSpace(fingerprint) == "" {
			return errors.New("log fingerprint must not be empty")
		}
		if _, exists := known[fingerprint]; exists {
			continue
		}
		known[fingerprint] = struct{}{}
		current = append(current, fingerprint)
	}

	if len(current) > MaximumFingerprints {
		current = append([]string(nil), current[len(current)-MaximumFingerprints:]...)
	}

	return s.write(scope, current)
}

func (s *Store) load(scope string) (map[string]struct{}, error) {
	values, err := s.loadOrdered(scope)
	if err != nil {
		return nil, err
	}

	known := make(map[string]struct{}, len(values))
	for _, value := range values {
		known[value] = struct{}{}
	}

	return known, nil
}

func (s *Store) loadOrdered(scope string) ([]string, error) {
	content, err := os.ReadFile(s.path(scope))
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read log deduplication state: %w", err)
	}

	var values []string
	if err := json.Unmarshal(content, &values); err != nil {
		return nil, fmt.Errorf("decode log deduplication state: %w", err)
	}
	if len(values) > MaximumFingerprints {
		return nil, errors.New("log deduplication state exceeds its configured bound")
	}

	return values, nil
}

func (s *Store) write(scope string, values []string) error {
	content, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("encode log deduplication state: %w", err)
	}
	content = append(content, '\n')

	temporary, err := os.CreateTemp(s.directory, ".log-dedupe-*.tmp")
	if err != nil {
		return fmt.Errorf("create log deduplication state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure log deduplication state: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return fmt.Errorf("write log deduplication state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync log deduplication state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close log deduplication state: %w", err)
	}
	if err := os.Rename(temporaryPath, s.path(scope)); err != nil {
		return fmt.Errorf("replace log deduplication state: %w", err)
	}

	directory, err := os.Open(s.directory)
	if err != nil {
		return fmt.Errorf("open log deduplication directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync log deduplication directory: %w", err)
	}

	return nil
}

func (s *Store) path(scope string) string {
	digest := sha256.Sum256([]byte(scope))
	return filepath.Join(s.directory, hex.EncodeToString(digest[:])+".json")
}
