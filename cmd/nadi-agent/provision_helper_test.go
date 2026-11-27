package main

import (
	"bytes"
	"testing"
)

func TestIsProvisionHelperInvocation(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "fixed helper path", path: "/usr/libexec/nadi/nadi-provision", want: true},
		{name: "helper basename", path: "nadi-provision", want: true},
		{name: "agent executable", path: "/opt/nadi/bin/nadi-agent", want: false},
		{name: "different executable", path: "/usr/libexec/nadi/other", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isProvisionHelperInvocation(test.path); got != test.want {
				t.Fatalf("isProvisionHelperInvocation(%q) = %t, want %t", test.path, got, test.want)
			}
		})
	}
}

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
