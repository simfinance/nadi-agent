package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const integrityKeyFilename = "state-integrity-private.pem"

func loadOrCreateIntegrityKey(directory string) (ed25519.PrivateKey, error) {
	key, err := loadExistingIntegrityKey(directory)
	if err == nil {
		return key, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	statePath := filepath.Join(directory, "state.json")
	if _, statErr := os.Lstat(statePath); statErr == nil {
		return nil, errors.New("Agent state exists but its integrity key is missing; recovery is required")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect existing Agent state: %w", statErr)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 state integrity key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("encode Ed25519 state integrity key: %w", err)
	}

	content := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	path := filepath.Join(directory, integrityKeyFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create Agent state integrity key: %w", err)
	}

	if _, err := file.Write(content); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("write Agent state integrity key: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("sync Agent state integrity key: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("close Agent state integrity key: %w", err)
	}

	directoryFile, err := os.Open(directory)
	if err != nil {
		return nil, fmt.Errorf("open state directory for key sync: %w", err)
	}
	defer directoryFile.Close()

	if err := directoryFile.Sync(); err != nil {
		return nil, fmt.Errorf("sync state directory after key creation: %w", err)
	}

	return privateKey, nil
}

func loadExistingIntegrityKey(directory string) (ed25519.PrivateKey, error) {
	path := filepath.Join(directory, integrityKeyFilename)
	metadata, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	stat, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok ||
		metadata.Mode()&os.ModeSymlink != 0 ||
		!metadata.Mode().IsRegular() ||
		stat.Uid != uint32(os.Geteuid()) ||
		metadata.Mode().Perm() != 0600 ||
		metadata.Size() < 1 ||
		metadata.Size() > 4096 {
		return nil, errors.New("Agent state integrity key ownership, permissions, or file type are unsafe")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Agent state integrity key: %w", err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened Agent state integrity key: %w", err)
	}
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok ||
		openedStat.Dev != stat.Dev ||
		openedStat.Ino != stat.Ino ||
		openedStat.Uid != uint32(os.Geteuid()) ||
		!opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0600 {
		return nil, errors.New("Agent state integrity key changed during read")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Agent state integrity key: %w", err)
	}

	block, rest := pem.Decode(content)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, errors.New("Agent state integrity key is not valid PKCS#8 PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Agent state integrity key: %w", err)
	}

	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("Agent state integrity key must be Ed25519")
	}

	return append(ed25519.PrivateKey(nil), privateKey...), nil
}

func signIntegrity(current *State, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("Agent state integrity private key is invalid")
	}

	current.IntegritySignature = ""
	content, err := jsonStateForSignature(*current)
	if err != nil {
		return err
	}

	current.IntegritySignature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(privateKey, content),
	)

	return nil
}

func verifyIntegrity(current State, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("Agent state integrity public key is invalid")
	}
	if current.IntegritySignature == "" {
		return errors.New("Agent state has no Ed25519 integrity signature")
	}

	signature, err := base64.StdEncoding.DecodeString(current.IntegritySignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("Agent state integrity signature is malformed")
	}

	current.IntegritySignature = ""
	content, err := jsonStateForSignature(current)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, content, signature) {
		return errors.New("Agent state Ed25519 integrity verification failed")
	}

	return nil
}
