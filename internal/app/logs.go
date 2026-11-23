package app

import (
	"encoding/json"
	"errors"
	"fmt"

	"nadi-agent/internal/logdedupe"
)

type applicationLogSummaryPayload struct {
	Source  string                       `json:"source"`
	Entries []applicationLogSummaryEntry `json:"entries"`
}

type applicationLogSummaryEntry struct {
	Timestamp     string `json:"timestamp"`
	Level         string `json:"level"`
	ExceptionType string `json:"exception_type"`
	Fingerprint   string `json:"fingerprint"`
}

func filterApplicationLogSummary(
	store *logdedupe.Store,
	applicationID string,
	data json.RawMessage,
) (json.RawMessage, []string, error) {
	if store == nil {
		return nil, nil, errors.New("log fingerprint store is unavailable")
	}
	if applicationID == "" {
		return nil, nil, errors.New("application_id is required for log fingerprint isolation")
	}

	var payload applicationLogSummaryPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, nil, fmt.Errorf("decode Bridge application log summary: %w", err)
	}
	if payload.Source != "laravel_application" {
		return nil, nil, fmt.Errorf("unexpected Bridge application log source %q", payload.Source)
	}
	if len(payload.Entries) > 100 {
		return nil, nil, errors.New("Bridge application log response exceeds 100 entries")
	}

	fingerprints := make([]string, 0, len(payload.Entries))
	for index, entry := range payload.Entries {
		if entry.Fingerprint == "" {
			return nil, nil, fmt.Errorf("Bridge application log entry %d has no fingerprint", index)
		}
		fingerprints = append(fingerprints, entry.Fingerprint)
	}

	unseen, err := store.Unseen("application:"+applicationID, fingerprints)
	if err != nil {
		return nil, nil, fmt.Errorf("check application log fingerprints: %w", err)
	}

	allowed := make(map[string]struct{}, len(unseen))
	for _, fingerprint := range unseen {
		allowed[fingerprint] = struct{}{}
	}

	filtered := applicationLogSummaryPayload{
		Source:  payload.Source,
		Entries: make([]applicationLogSummaryEntry, 0, len(unseen)),
	}
	for _, entry := range payload.Entries {
		if _, exists := allowed[entry.Fingerprint]; exists {
			filtered.Entries = append(filtered.Entries, entry)
		}
	}

	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, nil, fmt.Errorf("encode filtered Bridge log summary: %w", err)
	}

	return encoded, unseen, nil
}
