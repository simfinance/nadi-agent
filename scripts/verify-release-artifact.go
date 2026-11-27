package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nadi-agent/internal/provision"
)

func main()
{
	if len(os.Args) != 5
	{
		fmt.Fprintln(os.Stderr, "usage: verify-release-artifact <manifest.json> <signature-base64> <agent-binary> <architecture>")
		os.Exit(2)
	}

	manifestPath := os.Args[1]
	signaturePath := os.Args[2]
	artifactPath := os.Args[3]
	architecture := os.Args[4]

	manifestJSON, err := readRegularFile(manifestPath, 1<<20)
	if err != nil
	{
		fail(err)
	}

	signatureBytes, err := readRegularFile(signaturePath, 4096)
	if err != nil
	{
		fail(err)
	}

	signature := strings.TrimSpace(string(signatureBytes))
	manifest, err := provision.VerifySignedRelease(manifestJSON, signature)
	if err != nil
	{
		fail(fmt.Errorf("verify signed release manifest: %w", err))
	}

	artifact, err := provision.SelectReleaseArtifact(manifest, architecture)
	if err != nil
	{
		fail(err)
	}

	if filepath.Base(artifactPath) != artifact.Filename
	{
		fail(errors.New("Agent artifact filename does not match the signed release manifest"))
	}

	if err := provision.VerifyReleaseArtifact(artifactPath, artifact); err != nil
	{
		fail(err)
	}

	fmt.Printf("%s\t%s\t%s\t%s\n",
		manifest.Version,
		artifact.Architecture,
		artifact.Filename,
		artifact.SHA256,
	)
}

func readRegularFile(path string, maximumSize int64) ([]byte, error)
{
	if path == "" || !filepath.IsAbs(path)
	{
		return nil, fmt.Errorf("input path must be absolute: %s", path)
	}

	metadata, err := os.Lstat(path)
	if err != nil
	{
		return nil, err
	}

	if metadata.Mode()&os.ModeSymlink != 0 || !metadata.Mode().IsRegular()
	{
		return nil, errors.New("release input must be a regular non-symlink file")
	}

	if metadata.Size() < 1 || metadata.Size() > maximumSize
	{
		return nil, errors.New("release input size is outside the allowed limit")
	}

	content, err := os.ReadFile(path)
	if err != nil
	{
		return nil, err
	}

	openedMetadata, err := os.Stat(path)
	if err != nil || !os.SameFile(metadata, openedMetadata)
	{
		return nil, errors.New("release input changed while being read")
	}

	return content, nil
}

func fail(err error)
{
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
