package provision

import "regexp"

const maximumProvisionRequestBytes = 64 * 1024

var enrollmentTokenPattern = regexp.MustCompile(`^nadi_enroll_[a-f0-9]{64}$`)

type ProvisionRequest struct {
    Release      ProvisionReleaseRequest
    Applications []ProvisionApplication
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
