package provision

import (
    "errors"
    "fmt"
    "os"
    "runtime"
    "strings"
)

func validateSupportedPlatform(goos string, goarch string, distroID string, systemdAvailable bool) error {
    if goos != "linux" {
        return fmt.Errorf("unsupported operating system %q; NADI Agent requires Ubuntu Linux", goos)
    }

    switch goarch {
    case "amd64", "arm64":
    default:
        return fmt.Errorf("unsupported architecture %q; supported architectures are amd64 and arm64", goarch)
    }

    if strings.ToLower(strings.TrimSpace(distroID)) != "ubuntu" {
        return fmt.Errorf("unsupported Linux distribution %q; NADI Agent currently supports Ubuntu only", distroID)
    }

    if !systemdAvailable {
        return errors.New("systemd is required to install and manage NADI Agent")
    }

    return nil
}

func validateSupportedHost() error {
    release, err := os.ReadFile("/etc/os-release")
    if err != nil {
        return fmt.Errorf("read operating system release metadata: %w", err)
    }

    distroID := ""
    for _, line := range strings.Split(string(release), "\n") {
        if strings.HasPrefix(line, "ID=") {
            distroID = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "ID=")), "\"'")
            break
        }
    }

    systemdAvailable := false
    if metadata, err := os.Stat("/run/systemd/system"); err == nil && metadata.IsDir() {
        if command, err := os.Stat("/usr/bin/systemctl"); err == nil && command.Mode().IsRegular() && command.Mode().Perm()&0111 != 0 {
            systemdAvailable = true
        }
    }

    return validateSupportedPlatform(runtime.GOOS, runtime.GOARCH, distroID, systemdAvailable)
}
