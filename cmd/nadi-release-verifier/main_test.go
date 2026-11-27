package main

import (
	"strings"
	"testing"

	"nadi-agent/internal/provision"
)

func TestFormatReleaseMetadataUsesTabDelimitedFields(t *testing.T) {
	manifest := provision.ReleaseManifest{
		Version: "1.2.3",
	}
	artifact := provision.ReleaseArtifact{
		Architecture: "amd64",
		Filename:     "nadi-agent-linux-amd64",
		SHA256:       strings.Repeat("a", 64),
	}

	got := formatReleaseMetadata(manifest, artifact)
	want := "1.2.3\\tamd64\\tnadi-agent-linux-amd64\\t" + strings.Repeat("a", 64) + "\\n"

	if got != want {
		t.Fatalf("formatReleaseMetadata() = %q, want %q", got, want)
	}
}
