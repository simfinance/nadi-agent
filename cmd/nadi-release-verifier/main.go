package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "nadi-agent/internal/provision"
)

func main() {
    if len(os.Args) != 5 {
        fmt.Fprintln(os.Stderr, "usage: nadi-release-verifier <manifest.json> <signature-base64> <agent-binary> <architecture>")
        os.Exit(2)
    }

    manifestJSON, err := readRegularFile(os.Args[1], 1<<20)
    if err != nil {
        fail(err)
    }

    signatureBytes, err := readRegularFile(os.Args[2], 4096)
    if err != nil {
        fail(err)
    }

    manifest, err := provision.VerifySignedRelease(manifestJSON, strings.TrimSpace(string(signatureBytes)))
    if err != nil {
        fail(fmt.Errorf("verify signed release manifest: %w", err))
    }

    artifact, err := provision.SelectReleaseArtifact(manifest, os.Args[4])
    if err != nil {
        fail(err)
    }

    if filepath.Base(os.Args[3]) != artifact.Filename {
        fail(errors.New("Agent artifact filename does not match the signed release manifest"))
    }

    if err := provision.VerifyReleaseArtifact(os.Args[3], artifact); err != nil {
        fail(err)
    }

    fmt.Print(formatReleaseMetadata(manifest, artifact))
}

func formatReleaseMetadata(manifest provision.ReleaseManifest, artifact provision.ReleaseArtifact) string {
    return fmt.Sprintf("%s\t%s\t%s\t%s\n",
        manifest.Version,
        artifact.Architecture,
        artifact.Filename,
        artifact.SHA256,
    )
}

func readRegularFile(path string, maximumSize int64) ([]byte, error) {
    if path == "" || !filepath.IsAbs(path) {
        return nil, errors.New("release input path must be absolute")
    }

    metadata, err := os.Lstat(path)
    if err != nil {
        return nil, err
    }

    if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular() {
        return nil, errors.New("release input must be a regular non-symlink file")
    }

    if metadata.Size() < 1 || metadata.Size() > maximumSize {
        return nil, errors.New("release input size is outside the allowed limit")
    }

    content, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }

    openedMetadata, err := os.Stat(path)
    if err != nil || !os.SameFile(metadata, openedMetadata) {
        return nil, errors.New("release input changed while being read")
    }

    return content, nil
}

func fail(err error) {
    fmt.Fprintln(os.Stderr, err)
    os.Exit(1)
}
