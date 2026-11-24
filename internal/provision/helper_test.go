package provision

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestSafeHelperMessageTruncatesLongErrors(t *testing.T) {
	message := safeHelperMessage(errors.New(strings.Repeat("x", 600)))
	if len(message) > 512 {
		t.Fatalf("helper message exceeded 512 bytes: %d", len(message))
	}
}
