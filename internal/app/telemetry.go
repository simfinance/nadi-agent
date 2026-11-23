package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"nadi-agent/internal/activation"
	"nadi-agent/internal/appmonitor"
	"nadi-agent/internal/appspool"
	"nadi-agent/internal/logtelemetry"
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
			if source.Kind == "server" && !serverStreamAllowed(decisions, source.Stream) {
				if err := a.telemetrySender.DiscardPending(); err != nil {
					return fmt.Errorf("quarantine pending server telemetry after capability gate closed: %w", err)
				}
				return nil
			}
			if source.Kind == "application" &&
				((source.Stream == "application_logs" && !a.config.LogTelemetryEnabled) ||
					!applicationStreamAllowed(decisions, source.ApplicationID, source.Stream)) {
				if err := a.telemetrySender.DiscardPending(); err != nil {
					return fmt.Errorf("quarantine pending application telemetry after capability gate closed: %w", err)
				}
				return nil
			}
		}
	}

	inputs := make([]telemetry.InputRecord, 0, 500)
	emptyApplicationEvents := make(map[string][]string)

	if serverMetricsAllowed {
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
	}

	for _, application := range agentState.Applications {
		if !applicationTelemetryAllowed(decisions, application.ApplicationID) {
			continue
		}

		decision := decisions[application.ApplicationID]
		maximumRecordsPerSnapshot := 0
		if hasCapability(decision.Capabilities, "application_metrics") {
			maximumRecordsPerSnapshot++
		}
		if hasCapability(decision.Capabilities, appmonitor.CapabilityDatabaseMonitoring) {
			maximumRecordsPerSnapshot++
		}
		if hasCapability(decision.Capabilities, appmonitor.CapabilityApplicationLogs) {
			maximumRecordsPerSnapshot += 100
		}
		if maximumRecordsPerSnapshot == 0 {
			continue
		}

		remaining := telemetry.MaximumBatchRecords - len(inputs)
		maximumSnapshots := remaining / maximumRecordsPerSnapshot
		if maximumSnapshots <= 0 {
			break
		}
		applicationRecords, err := a.applicationSpool.ReadBatch(application.ApplicationID, maximumSnapshots)
		if err != nil {
			return fmt.Errorf("read application telemetry spool for %s: %w", application.ApplicationID, err)
		}
		for _, record := range applicationRecords {
			inputCountBefore := len(inputs)
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

			if hasCapability(decision.Capabilities, appmonitor.CapabilityDatabaseMonitoring) &&
				(record.Payload.Database.Status == appmonitor.StatusAvailable || record.Payload.Database.Status == appmonitor.StatusDegraded) &&
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

			if a.config.LogTelemetryEnabled &&
				hasCapability(decision.Capabilities, appmonitor.CapabilityApplicationLogs) &&
				record.Payload.Logs.Status == appmonitor.StatusAvailable &&
				len(record.Payload.Logs.Data) > 0 {
				logInputs, err := buildApplicationLogInputs(record)
				if err != nil {
					return fmt.Errorf("normalize application log summary for %s: %w", application.ApplicationID, err)
				}
				inputs = append(inputs, logInputs...)
			}

			if len(inputs) == inputCountBefore &&
				hasCapability(decision.Capabilities, appmonitor.CapabilityApplicationLogs) &&
				(record.Payload.Logs.Status == appmonitor.StatusAvailable || record.Payload.Logs.Status == appmonitor.StatusUnsupported) {
				emptyApplicationEvents[record.ApplicationID] = append(
					emptyApplicationEvents[record.ApplicationID],
					record.EventID,
				)
			}
		}
	}

	for applicationID, eventIDs := range emptyApplicationEvents {
		if err := a.applicationSpool.Acknowledge(applicationID, eventIDs); err != nil {
			return fmt.Errorf("acknowledge empty application log collection for %s: %w", applicationID, err)
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
	quarantineStatuses := make(map[int]int)
	for _, source := range acknowledged {
		if source.Quarantined {
			quarantinedCount++
			quarantineStatuses[source.QuarantineStatus]++
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

func serverStreamAllowed(
	decisions map[string]activation.GateDecision,
	stream string,
) bool {
	requiredCapability, found := telemetry.RequiredCapability(stream)
	if !found || !telemetry.IsServerStream(stream) {
		return false
	}

	for _, decision := range decisions {
		if decision.Enabled && hasCapability(decision.Capabilities, requiredCapability) {
			return true
		}
	}
	return false
}

func applicationStreamAllowed(
	decisions map[string]activation.GateDecision,
	applicationID string,
	stream string,
) bool {
	requiredCapability, found := telemetry.RequiredCapability(stream)
	if !found || telemetry.IsServerStream(stream) {
		return false
	}

	decision, found := decisions[applicationID]
	return found && decision.Enabled && hasCapability(decision.Capabilities, requiredCapability)
}

type bridgeApplicationLogPayload struct {
	Source  string `json:"source"`
	Entries []struct {
		Timestamp     string `json:"timestamp"`
		Level         string `json:"level"`
		ExceptionType string `json:"exception_type"`
		Fingerprint   string `json:"fingerprint"`
	} `json:"entries"`
}

func buildApplicationLogInputs(record appspool.Record) ([]telemetry.InputRecord, error) {
	var payload bridgeApplicationLogPayload
	if err := json.Unmarshal(record.Payload.Logs.Data, &payload); err != nil {
		return nil, fmt.Errorf("decode Bridge application log summary: %w", err)
	}
	if payload.Source != "laravel_application" {
		return nil, fmt.Errorf("unexpected Bridge application log source %q", payload.Source)
	}
	if len(payload.Entries) > 100 {
		return nil, errors.New("Bridge application log response exceeds 100 entries")
	}

	applicationID := record.ApplicationID
	inputs := make([]telemetry.InputRecord, 0, len(payload.Entries))
	for index, entry := range payload.Entries {
		if len(entry.Fingerprint) != 64 {
			return nil, fmt.Errorf("Bridge application log entry %d has an invalid fingerprint", index)
		}
		if _, err := hex.DecodeString(entry.Fingerprint); err != nil {
			return nil, fmt.Errorf("Bridge application log entry %d has a non-hex fingerprint", index)
		}

		message := "Laravel application error (unclassified)"
		contextFields := map[string]any{
			"fingerprint": entry.Fingerprint,
		}
		if entry.ExceptionType != "" {
			message = "Laravel exception: " + entry.ExceptionType
			contextFields["exception_type"] = entry.ExceptionType
		}

		raw, err := json.Marshal(map[string]any{
			"timestamp": entry.Timestamp,
			"level":     entry.Level,
			"channel":   payload.Source,
			"message":   message,
			"context":   contextFields,
		})
		if err != nil {
			return nil, fmt.Errorf("encode application log summary %d: %w", index, err)
		}

		normalized, err := logtelemetry.NormalizeApplicationLog(raw)
		if err != nil {
			return nil, fmt.Errorf("validate application log summary %d: %w", index, err)
		}

		inputs = append(inputs, telemetry.InputRecord{
			Stream:        "application_logs",
			ObservedAt:    record.Timestamp,
			CollectedAt:   record.Timestamp,
			ApplicationID: &applicationID,
			Data:          normalized,
			Source: telemetry.Source{
				Kind:          "application",
				ApplicationID: record.ApplicationID,
				EventID:       record.EventID,
			},
		})
	}
	return inputs, nil
}
