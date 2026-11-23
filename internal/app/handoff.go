package app

import (
	"errors"
	"fmt"
	"time"

	"nadi-agent/internal/activation"
	"nadi-agent/internal/control"
	"nadi-agent/internal/handoff"
	"nadi-agent/internal/state"
)

func (a *App) publishBridgeHandoff(
	store *state.Store,
	current *state.State,
	pollData control.PollData,
	decisions map[string]activation.GateDecision,
) error {
	if a.handoffClient == nil {
		return errors.New("local handoff client is unavailable")
	}

	polledApplications := make(map[string]control.Application, len(pollData.Applications))
	for _, application := range pollData.Applications {
		polledApplications[application.ApplicationID] = application
	}

	var handoffErrors []error
	changed := false

	for index := range current.Applications {
		application := &current.Applications[index]

		if !application.BridgeCredentialPublished && application.ApplicationCredential != "" {
			credentialRequest := handoff.CredentialRequest{
				ApplicationID:  application.ApplicationID,
				ApplicationKey: application.ApplicationKey,
				Credential:     application.ApplicationCredential,
			}

			if err := a.handoffClient.PublishApplicationCredential(credentialRequest); err != nil {
				handoffErrors = append(handoffErrors, fmt.Errorf(
					"publish Bridge credential for application %s: %w",
					application.ApplicationID,
					err,
				))
			} else {
				application.BridgeCredentialPublished = true
				changed = true
			}
		}

		decision := decisions[application.ApplicationID]
		observedAt := time.Now().UTC()

		assertion := handoff.ActivationStateRequest{
			ApplicationID:     application.ApplicationID,
			ApplicationKey:    application.ApplicationKey,
			ActivationState:   inactiveActivationState(polledApplications[application.ApplicationID], decision.Enabled),
			MonitoringEnabled: false,
			GrantAcknowledged: false,
			Capabilities:      []string{},
			ObservedAt:        observedAt.Format(time.RFC3339Nano),
			ValidUntil:        observedAt.Add(5 * time.Minute).Format(time.RFC3339Nano),
		}

		if decision.Enabled {
			assertion.ActivationState = "active"
			assertion.MonitoringEnabled = true
			assertion.GrantAcknowledged = true
			assertion.Capabilities = append([]string(nil), decision.Capabilities...)
		}

		if err := a.handoffClient.PublishActivationState(assertion); err != nil {
			handoffErrors = append(handoffErrors, fmt.Errorf(
				"publish Bridge activation state for application %s: %w",
				application.ApplicationID,
				err,
			))
		}
	}

	if changed {
		if err := store.Save(*current); err != nil {
			handoffErrors = append(handoffErrors, fmt.Errorf("persist Bridge credential handoff status: %w", err))
		}
	}

	return errors.Join(handoffErrors...)
}

func inactiveActivationState(application control.Application, gateEnabled bool) string {
	if gateEnabled {
		return "active"
	}

	switch application.ActivationStatus {
	case "suspended":
		return "suspended"
	case "revoked":
		return "revoked"
	}

	if application.RegistrationStatus == "pending" {
		return "pending_approval"
	}

	if application.RegistrationStatus == "approved" {
		return "pending_activation"
	}

	return "unknown"
}
