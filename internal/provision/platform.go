package provision

import (
    "errors"
    "fmt"
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
