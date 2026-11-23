package provision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeProvisionRequestAcceptsMultipleApplications(t *testing.T) {
	enrollmentManifest, err := json.Marshal(provisionEnrollmentManifest{
		Applications: []provisionManifestApplication{
			{ApplicationKey: "application-one"},
			{ApplicationKey: "application-two"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := ProvisionRequest{
		ProtocolVersion: 1,
		Operation:       "install_agent",
		Release: ProvisionReleaseRequest{
			ManifestBase64:  base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1}`)),
			SignatureBase64: "signed-manifest-signature",
			ArtifactPath:    "/var/tmp/nadi-agent",
		},
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "application-one",
				BasePath:       "/srv/www/application-one",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
			{
				ApplicationKey: "application-two",
				BasePath:       "/srv/www/application-two",
				RuntimeUID:     1002,
				RuntimeGID:     1002,
			},
		},
		Enrollment: ProvisionEnrollment{
			ManifestBase64: base64.StdEncoding.EncodeToString(enrollmentManifest),
			Token:          "nadi_enroll_" + strings.Repeat("a", 64),
		},
	}

	content, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	decoded, releaseManifest, decodedEnrollmentManifest, err := DecodeProvisionRequest(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded.Applications) != 2 {
		t.Fatalf("expected two application mappings, got %d", len(decoded.Applications))
	}

	if string(releaseManifest) != `{"schema_version":1}` {
		t.Fatalf("unexpected release manifest: %s", releaseManifest)
	}

	if len(decodedEnrollmentManifest) == 0 || decoded.ProtocolVersion != 1 {
		t.Fatal("expected a decoded version 1 enrollment request")
	}
}

func TestDecodeProvisionRequestRejectsDuplicateJSONKeys(t *testing.T) {
	content := []byte(`{"protocol_version":1,"protocol_version":1}`)

	if _, _, _, err := DecodeProvisionRequest(bytes.NewReader(content)); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
}

func TestValidateProvisionRequestRejectsDuplicateRuntimeUID(t *testing.T) {
	request := validProvisionRequest(t)
	request.Applications[1].RuntimeUID = request.Applications[0].RuntimeUID

	if _, _, err := validateProvisionRequest(request); err == nil {
		t.Fatal("duplicate runtime UID must be rejected")
	}
}

func TestValidateProvisionRequestRejectsOverlappingApplicationPaths(t *testing.T) {
	request := validProvisionRequest(t)
	request.Applications[1].BasePath = "/srv/www/application-one/nested"

	if _, _, err := validateProvisionRequest(request); err == nil {
		t.Fatal("overlapping application paths must be rejected")
	}
}

func TestValidateProvisionRequestRejectsMissingApplicationMapping(t *testing.T) {
	request := validProvisionRequest(t)
	request.Applications = request.Applications[:1]

	if _, _, err := validateProvisionRequest(request); err == nil {
		t.Fatal("missing application mapping must be rejected")
	}
}

func TestDecodeProvisionRequestRejectsOversizedInput(t *testing.T) {
	content := bytes.NewReader(bytes.Repeat([]byte("x"), maximumProvisionRequestBytes+1))

	if _, _, _, err := DecodeProvisionRequest(content); err == nil {
		t.Fatal("oversized provisioning request must be rejected")
	}
}

func validProvisionRequest(t *testing.T) ProvisionRequest {
	t.Helper()

	enrollmentManifest := provisionEnrollmentManifest{
		Applications: []provisionManifestApplication{
			{ApplicationKey: "application-one"},
			{ApplicationKey: "application-two"},
		},
	}

	manifestJSON, err := json.Marshal(enrollmentManifest)
	if err != nil {
		t.Fatal(err)
	}

	return ProvisionRequest{
		ProtocolVersion: 1,
		Operation:       "install_agent",
		Release: ProvisionReleaseRequest{
			ManifestBase64:  base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1}`)),
			SignatureBase64: "signed-manifest-signature",
			ArtifactPath:    "/var/tmp/nadi-agent",
		},
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "application-one",
				BasePath:       "/srv/www/application-one",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
			{
				ApplicationKey: "application-two",
				BasePath:       "/srv/www/application-two",
				RuntimeUID:     1002,
				RuntimeGID:     1002,
			},
		},
		Enrollment: ProvisionEnrollment{
			ManifestBase64: base64.StdEncoding.EncodeToString(manifestJSON),
			Token:          "nadi_enroll_" + strings.Repeat("a", 64),
		},
	}
}
