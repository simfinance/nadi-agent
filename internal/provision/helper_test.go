package provision

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBoundedBufferAcceptsWithinLimit(t *testing.T) {
	buffer := boundedBuffer{maximum: 8}

	written, err := buffer.Write([]byte("nadi"))
	if err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if written != 4 {
		t.Fatalf("expected 4 bytes written, got %d", written)
	}
	if buffer.overflow {
		t.Fatal("buffer unexpectedly overflowed")
	}
	if buffer.buffer.String() != "nadi" {
		t.Fatalf("unexpected buffer content %q", buffer.buffer.String())
	}
}

func TestBoundedBufferRejectsOversizedWrite(t *testing.T) {
	buffer := boundedBuffer{maximum: 4}

	written, err := buffer.Write([]byte("12345"))
	if err != nil {
		t.Fatalf("Write returned an error: %v", err)
	}
	if written != 5 {
		t.Fatalf("expected writer to consume the supplied bytes, got %d", written)
	}
	if !buffer.overflow {
		t.Fatal("expected buffer overflow to be recorded")
	}
	if buffer.buffer.Len() != 0 {
		t.Fatalf("oversized output was retained: %q", buffer.buffer.String())
	}
}

func TestWriteHelperResponseUsesBoundedProtocolFields(t *testing.T) {
	var output bytes.Buffer

	writeHelperResponse(&output, HelperResponse{
		ProtocolVersion:  1,
		Success:          false,
		Phase:            "enrollment",
		EnrollmentStatus: "unknown",
		RetrySafe:        false,
		AgentVersion:     "unknown",
		ApplicationCount: 2,
		Message:          "Enrollment outcome is uncertain.",
	})

	var response map[string]any
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatalf("decode helper response: %v", err)
	}

	if len(response) != 8 {
		t.Fatalf("expected 8 protocol fields, got %d", len(response))
	}
	if response["phase"] != "enrollment" || response["enrollment_status"] != "unknown" {
		t.Fatalf("unexpected partial outcome response: %#v", response)
	}
	if response["retry_safe"] != false {
		t.Fatalf("uncertain enrollment must not be marked retry-safe: %#v", response)
	}
}

func TestValidateApplicationTargetsRequiresMatchingRootOwnedPHPFPMPool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("test requires root-owned temporary PHP-FPM configuration files")
	}

	runtimeUser, err := user.Lookup("www-data")
	if err != nil {
		t.Skip("www-data account is not available")
	}
	runtimeGroup, err := user.LookupGroup("www-data")
	if err != nil {
		t.Skip("www-data group is not available")
	}
	uid, err := strconv.Atoi(runtimeUser.Uid)
	if err != nil || uid < 1 {
		t.Skip("www-data UID is not a non-root identity")
	}
	gid, err := strconv.Atoi(runtimeGroup.Gid)
	if err != nil || gid < 1 {
		t.Skip("www-data GID is not a non-root identity")
	}

	root := t.TempDir()
	poolDirectory := filepath.Join(root, "8.3", "fpm", "pool.d")
	if err := os.MkdirAll(poolDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(poolDirectory, "www.conf")
	if err := os.WriteFile(poolPath, []byte("[www]\nuser = www-data\ngroup = www-data\n"), 0644); err != nil {
		t.Fatal(err)
	}

	applicationPath := filepath.Join(root, "application")
	if err := os.MkdirAll(applicationPath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(applicationPath, "artisan"), []byte("<?php\n"), 0644); err != nil {
		t.Fatal(err)
	}

	request := ProvisionRequest{
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "application-one",
				BasePath:       applicationPath,
				RuntimeUID:     uid,
				RuntimeGID:     gid,
			},
		},
	}

	if err := validateApplicationTargetsAt(request, root); err != nil {
		t.Fatalf("valid application and PHP-FPM mapping was rejected: %v", err)
	}
}

func TestValidateRootOwnedDirectoryChainRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := validateRootOwnedDirectoryChain(root, filepath.Join(link, "pool.d"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink directory component to be rejected, got %v", err)
	}
}

func TestValidateRootOwnedDirectoryChainRejectsDirectoryOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	err := validateRootOwnedDirectoryChain(root, outside)
	if err == nil {
		t.Fatal("directory outside the PHP-FPM configuration root must be rejected")
	}
}

func TestReadRootOwnedRegularFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.conf")
	if err := os.WriteFile(target, []byte("[www]\n"), 0600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(directory, "linked.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := readRootOwnedRegularFile(link, 64*1024); err == nil {
		t.Fatal("symlinked PHP-FPM pool configuration must be rejected")
	}
}

func TestSafeHelperMessageTruncatesLongErrors(t *testing.T) {
	message := safeHelperMessage(errors.New(strings.Repeat("x", 600)))
	if len(message) > 512 {
		t.Fatalf("helper message exceeded 512 bytes: %d", len(message))
	}
}

func TestAgentInstallationAssetsReuseVerifiedArtifactForHelper(t *testing.T) {
	artifact := []byte("signed release artifact")
	assets := agentInstallationAssets(artifact)

	var agentBinary *provisionAsset
	var helperBinary *provisionAsset

	for index := range assets {
		switch assets[index].path {
		case agentBinaryPath:
			agentBinary = &assets[index]
		case trustedProvisionHelperPath:
			helperBinary = &assets[index]
		}
	}

	if agentBinary == nil || helperBinary == nil {
		t.Fatal("Agent binary and trusted helper must both be installation assets")
	}

	if !bytes.Equal(agentBinary.content, artifact) || !bytes.Equal(helperBinary.content, artifact) {
		t.Fatal("Agent and helper must use the exact verified release artifact bytes")
	}

	if !bytes.Equal(agentBinary.content, helperBinary.content) {
		t.Fatal("Agent and helper installation assets must be byte-for-byte identical")
	}

	for _, binary := range []*provisionAsset{agentBinary, helperBinary} {
		if binary.mode != 0755 || binary.uid != 0 || binary.gid != 0 {
			t.Fatalf("binary %s must be installed root:root mode 0755", binary.path)
		}
	}
}
