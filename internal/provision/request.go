package provision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

const maximumProvisionRequestBytes = 64 * 1024

var enrollmentTokenPattern = regexp.MustCompile(`^nadi_enroll_[a-f0-9]{64}$`)

type ProvisionRequest struct {
	ProtocolVersion int                     `json:"protocol_version"`
	Operation       string                  `json:"operation"`
	Release         ProvisionReleaseRequest `json:"release"`
	Applications    []ProvisionApplication  `json:"applications"`
	Enrollment      ProvisionEnrollment     `json:"enrollment"`
}

type ProvisionReleaseRequest struct {
	ManifestBase64  string `json:"manifest_base64"`
	SignatureBase64 string `json:"signature_base64"`
	ArtifactPath    string `json:"artifact_path"`
}

type ProvisionApplication struct {
	ApplicationKey string `json:"application_key"`
	BasePath       string `json:"base_path"`
	RuntimeUID     int    `json:"runtime_uid"`
	RuntimeGID     int    `json:"runtime_gid"`
}

type ProvisionEnrollment struct {
	ManifestBase64 string `json:"manifest_base64"`
	Token          string `json:"token"`
}

type provisionEnrollmentManifest struct {
	Applications []provisionManifestApplication `json:"applications"`
}

type provisionManifestApplication struct {
	ApplicationKey   string `json:"application_key"`
	ApplicationName  string `json:"application_name"`
	Environment      string `json:"environment"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	PHPVersion       string `json:"php_version,omitempty"`
	BaseURL          string `json:"base_url"`
}

func DecodeProvisionRequest(reader io.Reader) (ProvisionRequest, []byte, []byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maximumProvisionRequestBytes+1))
	if err != nil {
		return ProvisionRequest{}, nil, nil, fmt.Errorf("read provisioning request: %w", err)
	}

	if len(content) == 0 || len(content) > maximumProvisionRequestBytes {
		return ProvisionRequest{}, nil, nil, errors.New("provisioning request is empty or exceeds the size limit")
	}

	if err := rejectDuplicateJSONKeys(content); err != nil {
		return ProvisionRequest{}, nil, nil, fmt.Errorf("provisioning request JSON is ambiguous: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()

	var request ProvisionRequest
	if err := decoder.Decode(&request); err != nil {
		return ProvisionRequest{}, nil, nil, fmt.Errorf("decode provisioning request: %w", err)
	}

	if err := ensureJSONEOF(decoder); err != nil {
		return ProvisionRequest{}, nil, nil, fmt.Errorf("provisioning request has trailing data: %w", err)
	}

	manifestJSON, enrollmentManifestJSON, err := validateProvisionRequest(request)
	if err != nil {
		return ProvisionRequest{}, nil, nil, err
	}

	return request, manifestJSON, enrollmentManifestJSON, nil
}

func validateProvisionRequest(request ProvisionRequest) ([]byte, []byte, error) {
	if request.ProtocolVersion != 1 || request.Operation != "install_agent" {
		return nil, nil, errors.New("unsupported provisioning protocol version or operation")
	}

	if strings.TrimSpace(request.Release.ManifestBase64) == "" ||
		strings.TrimSpace(request.Release.SignatureBase64) == "" ||
		strings.TrimSpace(request.Release.ArtifactPath) == "" {
		return nil, nil, errors.New("signed Agent release request is incomplete")
	}

	if !filepath.IsAbs(request.Release.ArtifactPath) ||
		filepath.Clean(request.Release.ArtifactPath) != request.Release.ArtifactPath {
		return nil, nil, errors.New("Agent artifact path must be absolute and canonical")
	}

	if !enrollmentTokenPattern.MatchString(request.Enrollment.Token) {
		return nil, nil, errors.New("one-time enrollment token format is invalid")
	}

	if len(request.Applications) < 1 || len(request.Applications) > 20 {
		return nil, nil, errors.New("provisioning request must contain between 1 and 20 applications")
	}

	if strings.TrimSpace(request.Enrollment.ManifestBase64) == "" {
		return nil, nil, errors.New("enrollment manifest is missing")
	}

	releaseManifestJSON, err := base64.StdEncoding.Strict().DecodeString(request.Release.ManifestBase64)
	if err != nil {
		return nil, nil, errors.New("signed release manifest base64 is invalid")
	}

	if len(releaseManifestJSON) == 0 || len(releaseManifestJSON) > maximumManifestBytes {
		return nil, nil, errors.New("signed release manifest is empty or too large")
	}

	enrollmentManifestJSON, err := base64.StdEncoding.Strict().DecodeString(request.Enrollment.ManifestBase64)
	if err != nil {
		return nil, nil, errors.New("enrollment manifest base64 is invalid")
	}

	if len(enrollmentManifestJSON) == 0 || len(enrollmentManifestJSON) > 32*1024 {
		return nil, nil, errors.New("enrollment manifest is empty or too large")
	}

	if err := rejectDuplicateJSONKeys(enrollmentManifestJSON); err != nil {
		return nil, nil, fmt.Errorf("enrollment manifest JSON is ambiguous: %w", err)
	}

	manifestDecoder := json.NewDecoder(bytes.NewReader(enrollmentManifestJSON))
	manifestDecoder.DisallowUnknownFields()

	var manifest provisionEnrollmentManifest
	if err := manifestDecoder.Decode(&manifest); err != nil {
		return nil, nil, fmt.Errorf("decode enrollment manifest: %w", err)
	}

	if err := ensureJSONEOF(manifestDecoder); err != nil {
		return nil, nil, fmt.Errorf("enrollment manifest has trailing data: %w", err)
	}

	if len(manifest.Applications) != len(request.Applications) {
		return nil, nil, errors.New("enrollment manifest and local application mapping counts do not match")
	}

	manifestKeys := make(map[string]struct{}, len(manifest.Applications))
	for _, application := range manifest.Applications {
		if application.ApplicationKey == "" ||
			strings.TrimSpace(application.ApplicationName) == "" ||
			strings.TrimSpace(application.Environment) == "" ||
			len(application.ApplicationKey) > 100 ||
			len(application.ApplicationName) > 255 ||
			len(application.Environment) > 50 ||
			len(application.FrameworkVersion) > 50 ||
			len(application.PHPVersion) > 30 {
			return nil, nil, errors.New("enrollment manifest contains invalid application identity fields")
		}

		applicationURL, urlErr := url.ParseRequestURI(application.BaseURL)
		if urlErr != nil || applicationURL.Scheme != "https" || applicationURL.Host == "" {
			return nil, nil, errors.New("enrollment manifest application base_url must be an absolute HTTPS URL")
		}

		if _, exists := manifestKeys[application.ApplicationKey]; exists {
			return nil, nil, errors.New("enrollment manifest contains duplicate application keys")
		}

		manifestKeys[application.ApplicationKey] = struct{}{}
	}

	seenUIDs := make(map[int]struct{}, len(request.Applications))
	seenPaths := make([]string, 0, len(request.Applications))
	seenKeys := make(map[string]struct{}, len(request.Applications))

	for _, application := range request.Applications {
		if application.ApplicationKey == "" || !filepath.IsAbs(application.BasePath) ||
			filepath.Clean(application.BasePath) != application.BasePath {
			return nil, nil, errors.New("application key and canonical absolute base path are required")
		}

		if application.RuntimeUID < 1 || application.RuntimeGID < 1 {
			return nil, nil, errors.New("application runtime UID and GID must be non-root positive integers")
		}

		if _, exists := manifestKeys[application.ApplicationKey]; !exists {
			return nil, nil, errors.New("local application mapping does not match the enrollment manifest")
		}

		if _, exists := seenKeys[application.ApplicationKey]; exists {
			return nil, nil, errors.New("local application mapping contains duplicate application keys")
		}

		if _, exists := seenUIDs[application.RuntimeUID]; exists {
			return nil, nil, errors.New("application runtime UIDs must be distinct for credential isolation")
		}

		for _, existingPath := range seenPaths {
			if application.BasePath == existingPath ||
				strings.HasPrefix(application.BasePath, existingPath+string(filepath.Separator)) ||
				strings.HasPrefix(existingPath, application.BasePath+string(filepath.Separator)) {
				return nil, nil, errors.New("application base paths must not overlap")
			}
		}

		seenKeys[application.ApplicationKey] = struct{}{}
		seenUIDs[application.RuntimeUID] = struct{}{}
		seenPaths = append(seenPaths, application.BasePath)
	}

	if len(seenKeys) != len(manifestKeys) {
		return nil, nil, errors.New("not every enrollment application has exactly one local mapping")
	}

	return releaseManifestJSON, enrollmentManifestJSON, nil
}
