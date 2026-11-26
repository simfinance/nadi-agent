package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateInstalledHelperExecutableAcceptsFixedRootOwnedPath(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "nadi-provision")

	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if err := validateInstalledHelperExecutable(
		executablePath,
		executablePath,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err != nil {
		t.Fatalf("valid installed helper was rejected: %v", err)
	}
}

func TestValidateInstalledHelperExecutableRejectsUnexpectedPath(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "nadi-provision")

	if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	expectedPath := filepath.Join(directory, "trusted", "nadi-provision")
	if err := validateInstalledHelperExecutable(
		executablePath,
		expectedPath,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("helper outside the fixed installation path must be rejected")
	}
}

func TestValidateInstalledHelperExecutableRejectsNonExecutableFile(t *testing.T) {
	directory := t.TempDir()
	executablePath := filepath.Join(directory, "nadi-provision")

	if err := os.WriteFile(executablePath, []byte("not executable"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := validateInstalledHelperExecutable(
		executablePath,
		executablePath,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("non-executable helper must be rejected")
	}
}

func TestValidateInstalledHelperExecutableRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	targetPath := filepath.Join(directory, "target")
	executablePath := filepath.Join(directory, "nadi-provision")

	if err := os.WriteFile(targetPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, executablePath); err != nil {
		t.Fatal(err)
	}

	if err := validateInstalledHelperExecutable(
		executablePath,
		executablePath,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
	); err == nil {
		t.Fatal("symlinked helper must be rejected")
	}
}

func TestValidateInstalledHelperExecutableRejectsSetIDPermissions(t *testing.T) {
	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "setuid", mode: os.ModeSetuid | 0755},
		{name: "setgid", mode: os.ModeSetgid | 0755},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			executablePath := filepath.Join(directory, "nadi-provision")

			if err := os.WriteFile(executablePath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(executablePath, test.mode); err != nil {
				t.Fatal(err)
			}

			if err := validateInstalledHelperExecutable(
				executablePath,
				executablePath,
				uint32(os.Geteuid()),
			); err == nil {
				t.Fatalf("helper with %s permissions must be rejected", test.name)
			}
		})
	}
}
