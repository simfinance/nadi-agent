package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"nadi-agent/internal/activation"
	"nadi-agent/internal/state"
	"nadi-agent/internal/telemetry"
)

var ErrControlPollRequired = errors.New("Central returned HTTP 410; refresh Control Poll immediately")

func (a *App) deliverTelemetry(
	ctx context.Context,
	agentState state.State,
	serverMetricsAllowed bool,
	decisions map[string]activation.GateDecision,
) error {
	pendingSources, hasPending, err := a.telemetrySender.PendingSources()
	if err != nil {
		return fmt.Errorf("inspect pending Central telemetry batch: %w", err)
	}
	if hasPending {
		for _, source := range pendingSources {
			if source.Kind == "server" && !serverMetricsAllowed {
				if err := a.telemetrySender.DiscardPending(); err != nil {
					return fmt.Errorf("discard telemetry batch after server Activation Gate closed: %w", err)
				}
				return nil
			}
			if source.Kind == "application" && !applicationTelemetryAllowed(decisions, source.ApplicationID) {
				if err := a.telemetrySender.DiscardPending(); err != nil {
					return fmt.Errorf("discard telemetry batch after application Activation Gate closed: %w", err)
				}
				return nil
			}
		}
	}

	inputs := make([]telemetry.InputRecord, 0, 500)

	serverRecords, err := a.telemetrySpool.ReadBatch(telemetry.MaximumBatchRecords)
	if err != nil {
		return fmt.Errorf("read server telemetry spool: %w", err)
	}
	for _, record := range serverRecords {
		data, err := json.Marshal(record.Payload)
		if err != nil {
			return fmt.Errorf("encode server metrics snapshot: %w", err)
		}
		inputs = append(inputs, telemetry.InputRecord{
			Stream:      "server_metrics",
			ObservedAt:  record.Timestamp,
			CollectedAt: record.Timestamp,
			Data:        data,
			Source: telemetry.Source{
				Kind:    "server",
				EventID: record.EventID,
			},
		})
	}

	for _, application := range agentState.Applications {
		if !applicationTelemetryAllowed(decisions, application.ApplicationID) {
			continue
		}

		remaining := telemetry.MaximumBatchRecords - len(inputs)
		if remaining <= 0 {
			break
		}
		applicationRecords, err := a.applicationSpool.ReadBatch(application.ApplicationID, remaining)
		if err != nil {
			return fmt.Errorf("read application telemetry spool for %s: %w", application.ApplicationID, err)
		}
		decision := decisions[application.ApplicationID]
		for _, record := range applicationRecords {
			source := telemetry.Source{
				Kind:          "application",
				ApplicationID: record.ApplicationID,
				EventID:       record.EventID,
			}
			applicationID := record.ApplicationID

			if hasCapability(decision.Capabilities, "application_metrics") {
				data, err := json.Marshal(map[string]any{
					"timestamp": record.Timestamp,
					"health":    record.Payload.Health,
					"info":      record.Payload.Info,
					"metrics":   record.Payload.Metrics,
				})
				if err != nil {
					return fmt.Errorf("encode application metrics snapshot: %w", err)
				}

				inputs = append(inputs, telemetry.InputRecord{
					Stream:        "application_metrics",
					ObservedAt:    record.Timestamp,
					CollectedAt:   record.Timestamp,
					ApplicationID: &applicationID,
					Data:          data,
					Source:        source,
				})
			}

			if hasCapability(decision.Capabilities, "database_monitoring") &&
				(record.Payload.Database.Status == "available" || record.Payload.Database.Status == "degraded") &&
				len(record.Payload.Database.Data) > 0 {
				inputs = append(inputs, telemetry.InputRecord{
					Stream:        "database_metrics",
					ObservedAt:    record.Timestamp,
					CollectedAt:   record.Timestamp,
					ApplicationID: &applicationID,
					Data:          append(json.RawMessage(nil), record.Payload.Database.Data...),
					Source:        source,
				})
			}
		}
	}

	acknowledged, err := a.telemetrySender.Send(
		ctx,
		agentState.CentralAgentID,
		agentState.AgentInstanceID,
		a.controlHTTP.Token,
		inputs,
	)
	if err != nil {
		var statusError *telemetry.HTTPStatusError
		if errors.As(err, &statusError) && statusError.StatusCode == http.StatusGone {
			return ErrControlPollRequired
		}
		return err
	}
	if len(acknowledged) == 0 {
		return nil
	}

	serverEventIDs := make([]string, 0, len(acknowledged))
	applicationEventIDs := make(map[string][]string)
	quarantinedCount := 0
	for _, source := range acknowledged {
		if source.Quarantined {
			quarantinedCount++
		}
		switch source.Kind {
		case "server":
			serverEventIDs = append(serverEventIDs, source.EventID)
		case "application":
			applicationEventIDs[source.ApplicationID] = append(applicationEventIDs[source.ApplicationID], source.EventID)
		default:
			return fmt.Errorf("unknown acknowledged telemetry source kind %q", source.Kind)
		}
	}

	if err := a.telemetrySpool.Acknowledge(serverEventIDs); err != nil {
		return fmt.Errorf("acknowledge completed server telemetry: %w", err)
	}
	for applicationID, eventIDs := range applicationEventIDs {
		if err := a.applicationSpool.Acknowledge(applicationID, eventIDs); err != nil {
			return fmt.Errorf("acknowledge completed telemetry for application %s: %w", applicationID, err)
		}
	}
	if err := a.telemetrySender.Complete(); err != nil {
		return fmt.Errorf("finalize telemetry batch: %w", err)
	}

	for _, source := range acknowledged {
		if source.QuarantineStatus == http.StatusGone {
			return ErrControlPollRequired
		}
	}

	a.logger.Info(
		"Telemetry delivery disposition persisted; local spool records acknowledged",
		"record_count", len(acknowledged),
		"quarantined_count", quarantinedCount,
	)
	return nil
}

func applicationTelemetryAllowed(
	decisions map[string]activation.GateDecision,
	applicationID string,
) bool {
	decision, found := decisions[applicationID]

	return found && decision.Enabled && hasApplicationMonitoringCapability(decision.Capabilities)
}
