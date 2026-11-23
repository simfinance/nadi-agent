package provision

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedReleasePublicKeyFingerprint(t *testing.T) {
	publicKey, err := trustedReleasePublicKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(publicKey) != 32 {
		t.Fatalf("expected a 32-byte Ed25519 public key, got %d", len(publicKey))
	}
}

func TestValidateReleaseManifestAcceptsSupportedManifest(t *testing.T) {
	manifest := ReleaseManifest{
		SchemaVersion:   1,
		Product:         "nadi-agent",
		KeyID:           trustedReleaseKeyID,
		Version:         "0.7.0",
		ProtocolVersion: 1,
		ReleasedAt:      "2026-11-23T00:00:00Z",
		Artifacts: []ReleaseArtifact{
			{
				OS:           "linux",
				Architecture: "amd64",
				Filename:     "nadi-agent-linux-amd64",
				URL:          "https://releases.example.test/nadi-agent-linux-amd64",
				SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
			{
				OS:           "linux",
				Architecture: "arm64",
				Filename:     "nadi-agent-linux-arm64",
				URL:          "https://releases.example.test/nadi-agent-linux-arm64",
				SHA256:       "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
	}

	if err := validateReleaseManifest(manifest); err != nil {
		t.Fatalf("valid release manifest was rejected: %v", err)
	}

	artifact, err := SelectReleaseArtifact(manifest, "x86_64")
	if err != nil {
		t.Fatal(err)
	}

	if artifact.Architecture != "amd64" {
		t.Fatalf("expected amd64 artifact, got %q", artifact.Architecture)
	}
}

func TestValidateReleaseManifestRejectsWrongKeyID(t *testing.T) {
	manifest := ReleaseManifest{
		SchemaVersion:   1,
		Product:         "nadi-agent",
		KeyID:           "untrusted-key",
		Version:         "0.7.0",
		ProtocolVersion: 1,
		ReleasedAt:      "2026-11-23T00:00:00Z",
		Artifacts: []ReleaseArtifact{
			{
				OS:           "linux",
				Architecture: "amd64",
				Filename:     "nadi-agent",
				URL:          "https://releases.example.test/nadi-agent",
				SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			},
		},
	}

	if err := validateReleaseManifest(manifest); err == nil {
		t.Fatal("manifest with an untrusted key ID must be rejected")
	}
}

func TestRejectDuplicateJSONKeys(t *testing.T) {
	content := []byte(`{"schema_version":1,"schema_version":1}`)

	if err := rejectDuplicateJSONKeys(content); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
}

func TestSelectReleaseArtifactRejectsUnsupportedArchitecture(t *testing.T) {
	_, err := SelectReleaseArtifact(ReleaseManifest{}, "386")

	if err == nil {
		t.Fatal("unsupported architecture must be rejected")
	}
}

func TestVerifyReleaseArtifactChecksSHA256(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "nadi-agent")
	content := []byte("trusted agent artifact")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(content)
	artifact := ReleaseArtifact{
		SHA256: hex.EncodeToString(digest[:]),
	}

	if err := VerifyReleaseArtifact(path, artifact); err != nil {
		t.Fatalf("valid artifact was rejected: %v", err)
	}

	artifact.SHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	if err := VerifyReleaseArtifact(path, artifact); err == nil {
		t.Fatal("artifact with a mismatched digest must be rejected")
	}
}

func TestVerifyReleaseArtifactRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "artifact")

	if err := os.WriteFile(target, []byte("artifact"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if err := VerifyReleaseArtifact(path, ReleaseArtifact{
		SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}); err == nil {
		t.Fatal("symlink artifact must be rejected")
	}
}
