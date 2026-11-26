package main

import (
	"fmt"
	"io"

	"nadi-agent/internal/provision"
)

func runProvisionHelper(
	args []string,
	executablePath string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
) int {
	if len(args) != 1 || args[0] != "--request-stdin" {
		fmt.Fprintln(stderr, "usage: nadi-provision --request-stdin")
		return 2
	}

	if err := provision.ValidateInstalledHelperExecutable(executablePath); err != nil {
		fmt.Fprintln(stderr, "provisioning helper installation is not trusted")
		return 126
	}

	return provision.RunPrivileged(stdin, stdout, stderr)
}
