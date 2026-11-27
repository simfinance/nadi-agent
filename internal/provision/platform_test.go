package provision

import "testing"

func TestValidateSupportedPlatform(t *testing.T) {
	tests := []struct {
		name             string
		goos             string
		goarch           string
		distroID         string
		systemdAvailable bool
		wantErr          bool
	}{
		{
			name:             "ubuntu amd64",
			goos:             "linux",
			goarch:           "amd64",
			distroID:         "ubuntu",
			systemdAvailable: true,
		},
		{
			name:             "ubuntu arm64",
			goos:             "linux",
			goarch:           "arm64",
			distroID:         "ubuntu",
			systemdAvailable: true,
		},
		{
			name:     "non linux",
			goos:     "windows",
			goarch:   "amd64",
			distroID: "ubuntu",
			wantErr:  true,
		},
		{
			name:             "unsupported architecture",
			goos:             "linux",
			goarch:           "386",
			distroID:         "ubuntu",
			systemdAvailable: true,
			wantErr:          true,
		},
		{
			name:             "non ubuntu distribution",
			goos:             "linux",
			goarch:           "amd64",
			distroID:         "debian",
			systemdAvailable: true,
			wantErr:          true,
		},
		{
			name:     "systemd unavailable",
			goos:     "linux",
			goarch:   "amd64",
			distroID: "ubuntu",
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateSupportedPlatform(
				test.goos,
				test.goarch,
				test.distroID,
				test.systemdAvailable,
			)

			if test.wantErr && err == nil {
				t.Fatal("expected unsupported platform to be rejected")
			}

			if !test.wantErr && err != nil {
				t.Fatalf("expected supported platform, got error: %v", err)
			}
		})
	}
}
