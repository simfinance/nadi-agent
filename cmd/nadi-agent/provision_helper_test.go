package main

import (
	"bytes"
	"testing"
)

func TestRunProvisionHelperRejectsUnexpectedArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runProvisionHelper(
		[]string{"--request-stdin", "--unexpected"},
		"/usr/libexec/nadi/nadi-provision",
		bytes.NewBufferString("{}"),
		&stdout,
		&stderr,
	)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stderr.String() != "usage: nadi-provision --request-stdin\n" {
		t.Fatalf("unexpected usage response: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}

func TestRunProvisionHelperRejectsExecutableOutsideFixedPath(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := runProvisionHelper(
		[]string{"--request-stdin"},
		"/tmp/nadi-provision",
		bytes.NewBufferString("{}"),
		&stdout,
		&stderr,
	)

	if exitCode != 126 {
		t.Fatalf("expected exit code 126, got %d", exitCode)
	}
	if stderr.String() != "provisioning helper installation is not trusted\n" {
		t.Fatalf("unexpected error response: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
}
