package provision

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

const trustedProvisionHelperPath = "/usr/libexec/nadi/nadi-provision"

// ValidateInstalledHelperExecutable verifies that the running helper is the
// fixed, root-owned executable expected by the privileged invocation boundary.
func ValidateInstalledHelperExecutable(executablePath string) error {
	return validateInstalledHelperExecutable(executablePath, trustedProvisionHelperPath, 0)
}

func validateInstalledHelperExecutable(executablePath string, expectedPath string, expectedUID uint32) error {
	if !filepath.IsAbs(executablePath) ||
		filepath.Clean(executablePath) != executablePath ||
		executablePath != expectedPath {
		return errors.New("provisioning helper must run from its fixed installation path")
	}

	resolvedPath, err := validateTrustedCommandPath(executablePath, expectedUID)
	if err != nil {
		return err
	}
	if resolvedPath != expectedPath {
		return errors.New("provisioning helper resolved outside its fixed installation path")
	}

	metadata, err := os.Lstat(resolvedPath)
	if err != nil {
		return err
	}
	if metadata.Mode()&os.ModeSetuid != 0 || metadata.Mode()&os.ModeSetgid != 0 {
		return errors.New("provisioning helper must not have setuid or setgid permissions")
	}
	if metadata.Mode().Perm()&0111 == 0 {
		return errors.New("provisioning helper must be executable")
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return errors.New("provisioning helper must be owned by the expected privileged identity")
	}

	return nil
}
