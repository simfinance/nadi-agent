package provision

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTrustedCommandPathAcceptsRootOwnedExecutable(t *testing.T) {
	directory := t.TempDir()
	commandPath := filepath.Join(directory, "systemctl")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	resolvedPath, err := validateTrustedCommandPath(commandPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("valid trusted command path was rejected: %v", err)
	}
	if resolvedPath != commandPath {
		t.Fatalf("expected resolved path %q, got %q", commandPath, resolvedPath)
	}
}

func TestValidateTrustedCommandPathResolvesTrustedParentSymlink(t *testing.T) {
	root := t.TempDir()
	binDirectory := filepath.Join(root, "bin")
	if err := os.Mkdir(binDirectory, 0755); err != nil {
		t.Fatal(err)
	}

	commandPath := filepath.Join(binDirectory, "systemctl")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	aliasDirectory := filepath.Join(root, "sbin")
	if err := os.Symlink(binDirectory, aliasDirectory); err != nil {
		t.Fatal(err)
	}

	resolvedPath, err := validateTrustedCommandPath(
		filepath.Join(aliasDirectory, "systemctl"),
		uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatalf("trusted parent symlink was rejected: %v", err)
	}
	if resolvedPath != commandPath {
		t.Fatalf("expected resolved path %q, got %q", commandPath, resolvedPath)
	}
}

func TestValidateTrustedCommandPathRejectsWritableParent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0777); err != nil {
		t.Fatal(err)
	}

	commandPath := filepath.Join(directory, "systemctl")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := validateTrustedCommandPath(commandPath, uint32(os.Geteuid())); err == nil {
		t.Fatal("group/other-writable command parent must be rejected")
	}
}

func TestValidateTrustedCommandPathRejectsSymlinkExecutable(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	commandPath := filepath.Join(directory, "systemctl")
	if err := os.Symlink(target, commandPath); err != nil {
		t.Fatal(err)
	}

	if _, err := validateTrustedCommandPath(commandPath, uint32(os.Geteuid())); err == nil {
		t.Fatal("symlink executable must be rejected")
	}
}

func TestValidateTrustedCommandPathRejectsWritableExecutable(t *testing.T) {
	directory := t.TempDir()
	commandPath := filepath.Join(directory, "systemctl")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(commandPath, 0777); err != nil {
		t.Fatal(err)
	}

	if _, err := validateTrustedCommandPath(commandPath, uint32(os.Geteuid())); err == nil {
		t.Fatal("group/other-writable executable must be rejected")
	}
}
