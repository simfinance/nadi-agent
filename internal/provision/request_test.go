package provision

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "strings"
    "testing"
)

func TestValidateInstallOperationRejectsDuplicateRuntimeUID(t *testing.T) {
    request := validInstallOperationRequest()
    request.Applications[1].RuntimeUID = request.Applications[0].RuntimeUID

    if err := validateProvisionOperationRequest(request); err == nil {
        t.Fatal("duplicate runtime UID must be rejected")
    }
}

func TestValidateInstallOperationRejectsOverlappingApplicationPaths(t *testing.T) {
    request := validInstallOperationRequest()
    request.Applications[1].BasePath = "/srv/www/application-one/nested"

    if err := validateProvisionOperationRequest(request); err == nil {
        t.Fatal("overlapping application paths must be rejected")
    }
}

func TestDecodeProvisionOperationRejectsOversizedInput(t *testing.T) {
    content := bytes.NewReader(bytes.Repeat([]byte("x"), maximumProvisionRequestBytes+1))

    if _, err := DecodeProvisionOperationRequest(content); err == nil {
        t.Fatal("oversized provisioning request must be rejected")
    }
}

func TestDecodeProvisionOperationRejectsDuplicateJSONKeys(t *testing.T) {
    content := []byte(`{"protocol_version":1,"operation":"start_agent","operation":"install_agent"}`)

    if _, err := DecodeProvisionOperationRequest(bytes.NewReader(content)); err == nil {
        t.Fatal("duplicate JSON keys must be rejected")
    }
}

func TestMatchEnrollmentManifestRejectsMissingApplicationMapping(t *testing.T) {
    inventory := provisionInventory{
        ProtocolVersion: 1,
        AgentVersion: "0.7.5",
        Applications: []ProvisionApplication{
            {ApplicationKey: "application-one", BasePath: "/srv/www/one", RuntimeUID: 1001, RuntimeGID: 1001},
            {ApplicationKey: "application-two", BasePath: "/srv/www/two", RuntimeUID: 1002, RuntimeGID: 1002},
        },
    }
    manifest := provisionEnrollmentManifest{
        Applications: []provisionManifestApplication{
            {ApplicationKey: "application-one", ApplicationName: "One", Environment: "production", BaseURL: "https://one.example.test"},
        },
    }

    if err := matchEnrollmentManifestToInventory(manifest, inventory); err == nil {
        t.Fatal("manifest missing an installed application must be rejected")
    }
}

func TestMatchEnrollmentManifestRejectsNonHTTPSURL(t *testing.T) {
    inventory := provisionInventory{
        ProtocolVersion: 1,
        AgentVersion: "0.7.5",
        Applications: []ProvisionApplication{
            {ApplicationKey: "application-one", BasePath: "/srv/www/one", RuntimeUID: 1001, RuntimeGID: 1001},
        },
    }
    manifest := provisionEnrollmentManifest{
        Applications: []provisionManifestApplication{
            {ApplicationKey: "application-one", ApplicationName: "One", Environment: "production", BaseURL: "http://one.example.test"},
        },
    }

    if err := matchEnrollmentManifestToInventory(manifest, inventory); err == nil {
        t.Fatal("non-HTTPS application URL must be rejected")
    }
}

func TestValidateEnrollmentOperationRequiresOneTimeToken(t *testing.T) {
    request := ProvisionOperationRequest{
        ProtocolVersion: 1,
        Operation: "enroll_agent",
        Enrollment: &ProvisionEnrollment{
            ManifestBase64: base64.StdEncoding.EncodeToString([]byte(`{"applications":[]}`)),
            Token: "invalid-token",
        },
    }

    if err := validateProvisionOperationRequest(request); err == nil {
        t.Fatal("invalid one-time enrollment token must be rejected")
    }
}

func TestValidateInstallOperationRequiresUniqueApplicationKeys(t *testing.T) {
    request := validInstallOperationRequest()
    request.Applications[1].ApplicationKey = request.Applications[0].ApplicationKey

    if err := validateProvisionOperationRequest(request); err == nil {
        t.Fatal("duplicate application keys must be rejected")
    }
}

func validInstallOperationRequest() ProvisionOperationRequest {
    return ProvisionOperationRequest{
        ProtocolVersion: 1,
        Operation: "install_agent",
        Release: &ProvisionReleaseRequest{
            ManifestBase64: base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1}`)),
            SignatureBase64: "signature",
            ArtifactPath: "/srv/www/application-one/storage/app/private/nadi/releases/staging/nadi-agent",
        },
        Applications: []ProvisionApplication{
            {
                ApplicationKey: "application-one",
                BasePath: "/srv/www/application-one",
                RuntimeUID: 1001,
                RuntimeGID: 1001,
            },
            {
                ApplicationKey: "application-two",
                BasePath: "/srv/www/application-two",
                RuntimeUID: 1002,
                RuntimeGID: 1002,
            },
        },
    }
}

func TestEnrollmentTokenPatternRejectsWhitespace(t *testing.T) {
    token := "nadi_enroll_" + strings.Repeat("a", 64) + " "
    if enrollmentTokenPattern.MatchString(token) {
        t.Fatal("enrollment token with trailing whitespace must be rejected")
    }
}

var _ = json.Valid
