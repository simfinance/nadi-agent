package provision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	maximumManifestBytes         = 1 << 20
	trustedReleaseKeyID          = "nadi-agent-release-2026-01"
	trustedReleaseKeyFingerprint = "91d063a323ffb7feaad3e4bf39d750ec339b2206b74f762d11e1f291267a49e1"
)

//go:embed assets/release-signing-public.pem
var releasePublicKeyPEM []byte

type ReleaseManifest struct {
	SchemaVersion   int               `json:"schema_version"`
	Product         string            `json:"product"`
	KeyID           string            `json:"key_id"`
	Version         string            `json:"version"`
	ProtocolVersion int               `json:"protocol_version"`
	ReleasedAt      string            `json:"released_at"`
	Artifacts       []ReleaseArtifact `json:"artifacts"`
}

type ReleaseArtifact struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Filename     string `json:"filename"`
	URL          string `json:"url"`
	SHA256       string `json:"sha256"`
}

var (
	platformValuePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	filenamePattern      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	versionPattern       = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

func VerifySignedRelease(manifestJSON []byte, signatureBase64 string) (ReleaseManifest, error) {
	if len(manifestJSON) == 0 || len(manifestJSON) > maximumManifestBytes {
		return ReleaseManifest{}, errors.New("release manifest is empty or exceeds the allowed size")
	}

	publicKey, err := trustedReleasePublicKey()
	if err != nil {
		return ReleaseManifest{}, err
	}

	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ReleaseManifest{}, errors.New("release manifest signature is invalid")
	}

	if !ed25519.Verify(publicKey, manifestJSON, signature) {
		return ReleaseManifest{}, errors.New("release manifest signature verification failed")
	}

	if err := rejectDuplicateJSONKeys(manifestJSON); err != nil {
		return ReleaseManifest{}, fmt.Errorf("release manifest JSON is ambiguous: %w", err)
	}

	var manifest ReleaseManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestJSON))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&manifest); err != nil {
		return ReleaseManifest{}, fmt.Errorf("decode release manifest: %w", err)
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return ReleaseManifest{}, fmt.Errorf("release manifest has trailing data: %w", err)
	}

	if err := validateReleaseManifest(manifest); err != nil {
		return ReleaseManifest{}, err
	}

	return manifest, nil
}

func SelectReleaseArtifact(manifest ReleaseManifest, architecture string) (ReleaseArtifact, error) {
	normalizedArchitecture := ""

	switch architecture {
	case "amd64", "x86_64":
		normalizedArchitecture = "amd64"
	case "arm64", "aarch64":
		normalizedArchitecture = "arm64"
	default:
		return ReleaseArtifact{}, fmt.Errorf("unsupported Agent architecture %q", architecture)
	}

	var selected []ReleaseArtifact

	for _, artifact := range manifest.Artifacts {
		if artifact.OS == "linux" && artifact.Architecture == normalizedArchitecture {
			selected = append(selected, artifact)
		}
	}

	if len(selected) != 1 {
		return ReleaseArtifact{}, fmt.Errorf(
			"release manifest must contain exactly one Linux %s artifact",
			normalizedArchitecture,
		)
	}

	return selected[0], nil
}

func VerifyReleaseArtifact(path string, artifact ReleaseArtifact) error {
	if !digestPattern.MatchString(artifact.SHA256) {
		return errors.New("release artifact SHA-256 digest is malformed")
	}

	linkInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect staged Agent artifact: %w", err)
	}

	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return errors.New("staged Agent artifact must be a regular non-symlink file")
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open staged Agent artifact: %w", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened Agent artifact: %w", err)
	}

	if !os.SameFile(linkInfo, fileInfo) || !fileInfo.Mode().IsRegular() {
		return errors.New("staged Agent artifact changed while it was being opened")
	}

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash staged Agent artifact: %w", err)
	}

	actualDigest := hex.EncodeToString(hash.Sum(nil))

	if actualDigest != artifact.SHA256 {
		return errors.New("Agent artifact SHA-256 verification failed")
	}

	return nil
}

func validateReleaseManifest(manifest ReleaseManifest) error {
	if manifest.SchemaVersion != 1 || manifest.Product != "nadi-agent" {
		return errors.New("unsupported release manifest schema or product")
	}

	if manifest.KeyID != trustedReleaseKeyID {
		return errors.New("release manifest key ID does not match the trusted release key")
	}

	if !versionPattern.MatchString(manifest.Version) {
		return errors.New("release manifest version is invalid")
	}

	if manifest.ProtocolVersion < 1 {
		return errors.New("release manifest protocol_version is invalid")
	}

	releasedAt, err := time.Parse("2006-01-02T15:04:05Z", manifest.ReleasedAt)
	if err != nil || releasedAt.UTC().Format("2006-01-02T15:04:05Z") != manifest.ReleasedAt {
		return errors.New("release manifest released_at must be an ISO 8601 UTC timestamp")
	}

	if len(manifest.Artifacts) == 0 {
		return errors.New("release manifest contains no artifacts")
	}

	seenPlatforms := make(map[string]struct{}, len(manifest.Artifacts))

	for index, artifact := range manifest.Artifacts {
		if artifact.OS == "" || artifact.Architecture == "" || artifact.Filename == "" || artifact.URL == "" || artifact.SHA256 == "" {
			return fmt.Errorf("release artifact %d is missing a required field", index)
		}

		if !platformValuePattern.MatchString(artifact.OS) || !platformValuePattern.MatchString(artifact.Architecture) {
			return fmt.Errorf("release artifact %d has an invalid platform", index)
		}

		if !filenamePattern.MatchString(artifact.Filename) || artifact.Filename == "." || artifact.Filename == ".." {
			return fmt.Errorf("release artifact %d has an invalid filename", index)
		}

		artifactURL, err := url.ParseRequestURI(artifact.URL)
		if err != nil || artifactURL.Scheme != "https" || artifactURL.Host == "" || artifactURL.User != nil {
			return fmt.Errorf("release artifact %d URL must be a valid HTTPS URL", index)
		}

		if !digestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("release artifact %d SHA-256 digest is malformed", index)
		}

		platform := artifact.OS + ":" + artifact.Architecture

		if _, exists := seenPlatforms[platform]; exists {
			return errors.New("release manifest contains duplicate platform artifacts")
		}

		seenPlatforms[platform] = struct{}{}
	}

	return nil
}

func trustedReleasePublicKey() (ed25519.PublicKey, error) {
	block, rest := pem.Decode(releasePublicKeyPEM)

	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errors.New("embedded release signing public key is invalid")
	}

	der := block.Bytes
	fingerprint := sha256.Sum256(der)

	if hex.EncodeToString(fingerprint[:]) != trustedReleaseKeyFingerprint {
		return nil, errors.New("embedded release signing public key fingerprint mismatch")
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse embedded release signing public key: %w", err)
	}

	publicKey, ok := parsed.(ed25519.PublicKey)

	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("embedded release signing key is not Ed25519")
	}

	return append(ed25519.PublicKey(nil), publicKey...), nil
}

func rejectDuplicateJSONKeys(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()

	if err := consumeJSONValue(decoder); err != nil {
		return err
	}

	return ensureJSONEOF(decoder)
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)

	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})

		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}

			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}

			seen[key] = struct{}{}

			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		_, err := decoder.Token()
		return err

	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		_, err := decoder.Token()
		return err

	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any

	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON contains trailing values")
		}

		return err
	}

	return nil
}
