package provision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeProvisionOperationAcceptsInstallWithoutEnrollment(t *testing.T) {
	request := ProvisionOperationRequest{
		ProtocolVersion: 1,
		Operation:       "install_agent",
		Release: &ProvisionReleaseRequest{
			ManifestBase64:  base64.StdEncoding.EncodeToString([]byte(`{"schema_version":1}`)),
			SignatureBase64: "signature",
			ArtifactPath:    "/srv/app/storage/app/private/nadi/releases/staging/nadi-agent",
		},
		Applications: []ProvisionApplication{
			{
				ApplicationKey: "application-one",
				BasePath:       "/srv/app",
				RuntimeUID:     1001,
				RuntimeGID:     1001,
			},
		},
	}

	content, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeProvisionOperationRequest(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("install_agent request was rejected: %v", err)
	}
	if decoded.Operation != "install_agent" || decoded.Enrollment != nil {
		t.Fatalf("unexpected install_agent request: %#v", decoded)
	}
}

func TestDecodeProvisionOperationRejectsEnrollmentFieldsDuringInstall(t *testing.T) {
	content := []byte(`{
        "protocol_version": 1,
        "operation": "install_agent",
        "release": {
            "manifest_base64": "e30=",
            "signature_base64": "signature",
            "artifact_path": "/srv/app/storage/app/private/nadi/releases/staging/nadi-agent"
        },
        "applications": [{
            "application_key": "application-one",
            "base_path": "/srv/app",
            "runtime_uid": 1001,
            "runtime_gid": 1001
        }],
        "enrollment": {
            "manifest_base64": "e30=",
            "token": "not-allowed"
        }
    }`)

	if _, err := DecodeProvisionOperationRequest(bytes.NewReader(content)); err == nil {
		t.Fatal("install_agent must reject enrollment token fields")
	}
}

func TestDecodeProvisionOperationAcceptsEnrollmentOnly(t *testing.T) {
	manifest := `{"applications":[{
        "application_key":"application-one",
        "application_name":"Application One",
        "environment":"production",
        "base_url":"https://app.example.test"
    }]}`
	request := ProvisionOperationRequest{
		ProtocolVersion: 1,
		Operation:       "enroll_agent",
		Enrollment: &ProvisionEnrollment{
			ManifestBase64: base64.StdEncoding.EncodeToString([]byte(manifest)),
			Token:          "nadi_enroll_" + strings.Repeat("a", 64),
		},
	}

	content, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeProvisionOperationRequest(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("enroll_agent request was rejected: %v", err)
	}
	if decoded.Release != nil || len(decoded.Applications) != 0 || decoded.Enrollment == nil {
		t.Fatalf("enroll_agent accepted unexpected fields: %#v", decoded)
	}
}

func TestDecodeProvisionOperationAcceptsEmptyStartRequest(t *testing.T) {
	content := []byte(`{"protocol_version":1,"operation":"start_agent"}`)

	decoded, err := DecodeProvisionOperationRequest(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("start_agent request was rejected: %v", err)
	}
	if decoded.Operation != "start_agent" {
		t.Fatalf("unexpected operation %q", decoded.Operation)
	}
}

func TestDecodeProvisionOperationRejectsFieldsForStart(t *testing.T) {
	content := []byte(`{
        "protocol_version":1,
        "operation":"start_agent",
        "applications":[]
    }`)

	if _, err := DecodeProvisionOperationRequest(bytes.NewReader(content)); err == nil {
		t.Fatal("start_agent must reject caller-supplied fields")
	}
}

func TestDecodeProvisionOperationRejectsUnknownOperation(t *testing.T) {
	content := []byte(`{"protocol_version":1,"operation":"run_shell"}`)

	if _, err := DecodeProvisionOperationRequest(bytes.NewReader(content)); err == nil {
		t.Fatal("unknown helper operations must be rejected")
	}
}

func TestDecodeProvisionOperationRejectsDuplicateJSONKeys(t *testing.T) {
	content := []byte(`{"protocol_version":1,"operation":"start_agent","operation":"install_agent"}`)

	if _, err := DecodeProvisionOperationRequest(bytes.NewReader(content)); err == nil {
		t.Fatal("duplicate JSON keys must be rejected")
	}
}


func TestDecodeEnrollmentIdentitySummaryReturnsStableIdentity(t *testing.T) {
    summary := []byte(`{
        "protocol_version": 1,
        "enrollment_status": "registered",
        "agent_instance_id": "agent-instance-restore",
        "agent_id": "central-agent-restore",
        "server_id": "central-server-restore",
        "applications": [
            {
                "application_id": "00000000-0000-4000-8000-000000000001",
                "application_key": "application-one",
                "application_name": "Application One",
                "environment": "production",
                "registration_id": "registration-one"
            }
        ]
    }`)

    identity, err := decodeEnrollmentIdentitySummary(summary)
    if err != nil {
        t.Fatalf("valid enrollment identity summary was rejected: %v", err)
    }

    if identity.AgentInstanceID != "agent-instance-restore" ||
        identity.AgentID != "central-agent-restore" ||
        identity.ServerID != "central-server-restore" {
        t.Fatalf("unexpected identity summary: %#v", identity)
    }
}

func TestDecodeEnrollmentIdentitySummaryRejectsIncompleteIdentity(t *testing.T) {
    summary := []byte(`{
        "protocol_version": 1,
        "enrollment_status": "registered",
        "agent_instance_id": "agent-instance-restore",
        "applications": [
            {
                "application_id": "00000000-0000-4000-8000-000000000001",
                "application_key": "application-one"
            }
        ]
    }`)

    if _, err := decodeEnrollmentIdentitySummary(summary); err == nil {
        t.Fatal("incomplete Central identity must be rejected")
    }
}
