package provision

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func validateTrustedCommandPath(path string, expectedUID uint32) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("trusted system command path must be absolute and canonical")
	}

	metadata, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("trusted system command %s is unavailable: %w", path, err)
	}
	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
		return "", errors.New("trusted system command must be a regular non-symlink file")
	}

	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve trusted system command parent: %w", err)
	}
	if !filepath.IsAbs(resolvedParent) || filepath.Clean(resolvedParent) != resolvedParent {
		return "", errors.New("trusted system command parent is not canonical")
	}
	if err := ensureNoSymlinkPath(resolvedParent); err != nil {
		return "", fmt.Errorf("trusted system command parent path is unsafe: %w", err)
	}

	current := string(os.PathSeparator)
	for _, segment := range strings.Split(strings.TrimPrefix(resolvedParent, string(os.PathSeparator)), string(os.PathSeparator)) {
		if segment == "" {
			continue
		}

		current = filepath.Join(current, segment)
		directory, statErr := os.Lstat(current)
		if statErr != nil {
			return "", fmt.Errorf("inspect trusted system command directory: %w", statErr)
		}
		if directory.Mode()&os.ModeSymlink != 0 || !directory.IsDir() {
			return "", errors.New("trusted system command parent contains a symlink or non-directory component")
		}

		stat, ok := directory.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != expectedUID) {
			return "", errors.New("trusted system command parent directories must be root-owned or owned by the expected runtime")
		}
		if directory.Mode().Perm()&0022 != 0 &&
			!(stat.Uid == 0 && directory.Mode()&os.ModeSticky != 0) {
			return "", errors.New("trusted system command parent directories must not be group/other writable")
		}
	}

	resolvedPath := filepath.Join(resolvedParent, filepath.Base(path))
	executable, err := os.Lstat(resolvedPath)
	if err != nil {
		return "", fmt.Errorf("inspect resolved trusted system command: %w", err)
	}
	if executable.Mode()&os.ModeSymlink != 0 || !executable.Mode().IsRegular() {
		return "", errors.New("resolved trusted system command must be a regular non-symlink file")
	}

	stat, ok := executable.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return "", errors.New("trusted system command must have the expected owner")
	}
	if executable.Mode().Perm()&0022 != 0 || executable.Mode().Perm()&0111 == 0 {
		return "", errors.New("trusted system command must be executable and not group/other writable")
	}

	return resolvedPath, nil
}
