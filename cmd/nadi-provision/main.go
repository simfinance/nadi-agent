package main

import (
    "fmt"
    "os"

    "nadi-agent/internal/provision"
)

func main() {
    if len(os.Args) != 2 || os.Args[1] != "--request-stdin" {
        fmt.Fprintln(os.Stderr, "usage: nadi-provision --request-stdin")
        os.Exit(2)
    }

    executablePath, err := os.Executable()
    if err != nil {
        fmt.Fprintln(os.Stderr, "unable to resolve provisioning helper executable")
        os.Exit(126)
    }

    if err := provision.ValidateInstalledHelperExecutable(executablePath); err != nil {
        fmt.Fprintln(os.Stderr, "provisioning helper installation is not trusted")
        os.Exit(126)
    }

    exitCode := provision.RunPrivileged(os.Stdin, os.Stdout, os.Stderr)
    if exitCode != 0 {
        os.Exit(exitCode)
    }
}
