package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"nadi-agent/internal/nginxlogs"
	"nadi-agent/internal/state"
)

func (a *App) collectNginxErrorLogs(agentState state.State) {
	if a.nginxErrorLogs == nil || a.logDedupe == nil {
		return
	}

	snapshot, cursor, err := a.nginxErrorLogs.CollectWithCursor(time.Now().UTC())
	if err != nil {
		a.logger.Warn(
			"Nginx error log cursor collection failed; cursor was not advanced",
			"server_id", agentState.CentralServerID,
			"error", err,
		)
		return
	}
	if snapshot.Status != nginxlogs.StatusAvailable {
		if snapshot.Status == nginxlogs.StatusUnavailable {
			a.logger.Warn(
				"Nginx error log collection is unavailable",
				"server_id", agentState.CentralServerID,
				"error_code", snapshot.ErrorCode,
			)
		}
		return
	}
	if len(snapshot.Entries) == 0 {
		if err := a.nginxErrorLogs.Commit(cursor); err != nil {
			a.logger.Error("Nginx error log cursor could not be persisted", "error", err)
		}
		return
	}

	fingerprints := make([]string, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		fingerprints = append(fingerprints, nginxErrorLogFingerprint(entry))
	}

	unseen, err := a.logDedupe.Unseen("server:nginx", fingerprints)
	if err != nil {
		a.logger.Error("Nginx error log deduplication state could not be read", "error", err)
		return
	}

	allowed := make(map[string]struct{}, len(unseen))
	for _, fingerprint := range unseen {
		allowed[fingerprint] = struct{}{}
	}

	entries := make([]nginxlogs.Entry, 0, len(unseen))
	for _, entry := range snapshot.Entries {
		if _, exists := allowed[nginxErrorLogFingerprint(entry)]; exists {
			entries = append(entries, entry)
		}
	}
	if len(entries) == 0 {
		if err := a.nginxErrorLogs.Commit(cursor); err != nil {
			a.logger.Error("Nginx error log cursor could not be persisted after deduplication", "error", err)
		}
		return
	}

	records, err := a.telemetrySpool.AppendNginxErrorLogs(
		agentState.CentralServerID,
		agentState.CentralAgentID,
		entries,
	)
	if err != nil {
		a.logger.Error(
			"Nginx error log entries could not be fully persisted to the durable server spool; cursor was not advanced",
			"server_id", agentState.CentralServerID,
			"persisted_entry_count", len(records),
			"error", err,
		)
		return
	}

	if err := a.logDedupe.Commit("server:nginx", unseen); err != nil {
		a.logger.Error(
			"Nginx error log fingerprints could not be persisted after the spool append; duplicate entries may be collected again",
			"event_id", records[0].EventID,
			"error", err,
		)
	}
	if err := a.nginxErrorLogs.Commit(cursor); err != nil {
		a.logger.Error(
			"Nginx error log cursor could not be persisted after the durable spool append; duplicate entries may be collected again",
			"event_id", records[0].EventID,
			"error", err,
		)
		return
	}

	a.logger.Info(
		"Nginx error log entries collected and queued locally",
		"first_event_id", records[0].EventID,
		"server_id", records[0].ServerID,
		"entry_count", len(entries),
	)
}

func nginxErrorLogFingerprint(entry nginxlogs.Entry) string {
	value := fmt.Sprintf(
		"%s|%s|%s",
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.Severity,
		entry.Message,
	)
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
