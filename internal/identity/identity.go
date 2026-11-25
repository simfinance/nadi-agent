package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"nadi-agent/internal/state"
)

var ErrMachineIdentityChanged = errors.New("machine identity does not match the persisted NADI Agent state")

func Ensure(store *state.Store) (state.State, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return state.State{}, fmt.Errorf("read server hostname: %w", err)
	}

	fingerprint, err := machineFingerprint()
	if err != nil {
		return state.State{}, err
	}

	current, err := store.Load()
	if err == nil {
		if current.MachineFingerprint != fingerprint {
			return state.State{}, ErrMachineIdentityChanged
		}

		if current.Hostname != hostname {
			current.Hostname = hostname
			if err := store.Save(current); err != nil {
				return state.State{}, err
			}
		}

		return current, nil
	}

	if !errors.Is(err, state.ErrNotFound) {
		return state.State{}, err
	}

	instanceID, err := newUUID()
	if err != nil {
		return state.State{}, fmt.Errorf("generate agent instance ID: %w", err)
	}

	now := time.Now().UTC()
	current = state.State{
		AgentInstanceID:    instanceID,
		Hostname:           hostname,
		MachineFingerprint: fingerprint,
		EnrollmentStatus:   "unregistered",
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := store.Save(current); err != nil {
		return state.State{}, err
	}

	return current, nil
}

func VerifyReadOnly(directory string) (state.State, error) {
	current, err := state.LoadReadOnly(directory)
	if err != nil {
		return state.State{}, fmt.Errorf("load persisted Agent identity: %w", err)
	}

	fingerprint, err := machineFingerprint()
	if err != nil {
		return state.State{}, err
	}

	if current.MachineFingerprint == "" || current.MachineFingerprint != fingerprint {
		return state.State{}, ErrMachineIdentityChanged
	}

	if current.EnrollmentStatus != "registered" ||
		current.AgentInstanceID == "" ||
		current.CentralAgentID == "" ||
		current.CentralServerID == "" {
		return state.State{}, errors.New("persisted Agent enrollment identity is incomplete")
	}

	if len(current.Applications) < 1 || len(current.Applications) > 20 {
		return state.State{}, errors.New("persisted Agent application identity count is invalid")
	}

	applicationIDs := make(map[string]struct{}, len(current.Applications))
	registrationIDs := make(map[string]struct{}, len(current.Applications))
	for _, application := range current.Applications {
		if application.ApplicationID == "" || application.RegistrationID == "" {
			return state.State{}, errors.New("persisted Agent application identity is incomplete or duplicated")
		}

		if _, exists := applicationIDs[application.ApplicationID]; exists {
			return state.State{}, errors.New("persisted Agent application identity is incomplete or duplicated")
		}
		if _, exists := registrationIDs[application.RegistrationID]; exists {
			return state.State{}, errors.New("persisted Agent application identity is incomplete or duplicated")
		}

		applicationIDs[application.ApplicationID] = struct{}{}
		registrationIDs[application.RegistrationID] = struct{}{}
	}

	return current, nil
}

func machineFingerprint() (string, error) {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}

	for _, path := range paths {
		machineID, err := readMachineID(path)
		if err != nil || !validMachineID(machineID) {
			continue
		}

		digest := sha256.Sum256([]byte(machineID))
		return hex.EncodeToString(digest[:]), nil
	}

	return "", errors.New("stable machine ID not found; expected /etc/machine-id or /var/lib/dbus/machine-id")
}

func readMachineID(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	content, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return "", err
	}
	if len(content) > 64 {
		return "", errors.New("machine ID file exceeds the size limit")
	}

	return strings.TrimSpace(string(content)), nil
}

func validMachineID(machineID string) bool {
	if len(machineID) != 32 {
		return false
	}

	decoded, err := hex.DecodeString(machineID)
	if err != nil || len(decoded) != 16 {
		return false
	}

	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}

	return false
}

func newUUID() (string, error) {
	var value [16]byte

	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}

	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	), nil
}
