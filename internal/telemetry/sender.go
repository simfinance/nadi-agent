package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	EndpointPath        = "/api/v1/nadi/agent/telemetry/batches"
	MaximumBatchBytes   = 1024 * 1024
	MaximumRecordBytes  = 64 * 1024
	MaximumBatchRecords = 500
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

	streamCapabilities = map[string]string{
		"server_metrics":       "server_metrics",
		"nginx_metrics":        "server_metrics",
		"nginx_vhost_metrics":  "server_metrics",
		"nginx_error_logs":     "system_logs",
		"application_metrics":  "application_metrics",
		"application_logs":     "application_logs",
		"database_metrics":     "database_monitoring",
		"database_connections": "database_monitoring",
		"queue_metrics":        "queue_monitoring",
		"queue_jobs":           "queue_monitoring",
		"scheduler_metrics":    "scheduler_monitoring",
		"scheduler_events":     "scheduler_monitoring",
	}

	serverStreams = map[string]struct{}{
		"server_metrics":      {},
		"nginx_metrics":       {},
		"nginx_vhost_metrics": {},
		"nginx_error_logs":    {},
	}
)

type InputRecord struct {
	Stream        string          `json:"stream"`
	ObservedAt    time.Time       `json:"observed_at"`
	CollectedAt   time.Time       `json:"collected_at"`
	ApplicationID *string         `json:"application_id"`
	MetricSet     *string         `json:"metric_set"`
	Data          json.RawMessage `json:"data"`
	Source        Source          `json:"source"`
}

type Source struct {
	Kind             string `json:"kind"`
	ApplicationID    string `json:"application_id,omitempty"`
	EventID          string `json:"event_id"`
	Stream           string `json:"stream"`
	Quarantined      bool   `json:"quarantined,omitempty"`
	QuarantineStatus int    `json:"quarantine_status,omitempty"`
}

type Record struct {
	RecordID      string          `json:"record_id"`
	Stream        string          `json:"stream"`
	Sequence      uint64          `json:"sequence"`
	ObservedAt    time.Time       `json:"observed_at"`
	CollectedAt   time.Time       `json:"collected_at"`
	ApplicationID *string         `json:"application_id"`
	MetricSet     *string         `json:"metric_set"`
	Data          json.RawMessage `json:"data"`
}

type Batch struct {
	ProtocolVersion string    `json:"protocol_version"`
	BatchID         string    `json:"batch_id"`
	AgentInstanceID string    `json:"agent_instance_id"`
	SentAt          time.Time `json:"sent_at"`
	Records         []Record  `json:"records"`
}

type pendingBatch struct {
	Batch            Batch          `json:"batch"`
	Sources          []Source       `json:"sources"`
	CompletedSources []Source       `json:"completed_sources,omitempty"`
	Following        []pendingBatch `json:"following,omitempty"`
}

type QuarantineEntry struct {
	QuarantinedAt time.Time    `json:"quarantined_at"`
	StatusCode    int          `json:"status_code"`
	Reason        string       `json:"reason"`
	Pending       pendingBatch `json:"pending"`
}

type HTTPStatusError struct {
	StatusCode int
	Message    string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("Central telemetry endpoint returned HTTP %d: %s", e.StatusCode, e.Message)
}

type sequenceState struct {
	Values map[string]uint64 `json:"values"`
}

type Ack struct {
	Success bool `json:"success"`
	Data    struct {
		Success        bool   `json:"success"`
		BatchID        string `json:"batch_id"`
		Status         string `json:"status"`
		RecordCount    int    `json:"record_count"`
		AcceptedCount  int    `json:"accepted_count"`
		DuplicateCount int    `json:"duplicate_count"`
		RejectedCount  int    `json:"rejected_count"`
		Replayed       bool   `json:"replayed"`
	} `json:"data"`
}

type Sender struct {
	baseURL string
	client  *http.Client
	dir     string
}

func NewSender(baseURL string, directory string, timeout time.Duration) (*Sender, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("telemetry Central URL must be an absolute HTTPS URL without userinfo or fragment")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create telemetry sender state directory: %w", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("secure telemetry sender state directory: %w", err)
	}

	return &Sender{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dir: directory,
	}, nil
}

func RequiredCapability(stream string) (string, bool) {
	capability, found := streamCapabilities[stream]
	return capability, found
}

func IsServerStream(stream string) bool {
	_, found := serverStreams[stream]
	return found
}

func (s *Sender) Send(ctx context.Context, agentID string, instanceID string, credential string, inputs []InputRecord) ([]Source, error) {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(instanceID) == "" || strings.TrimSpace(credential) == "" {
		return nil, errors.New("Agent ID, Agent instance ID, and credential are required for telemetry delivery")
	}
	if !uuidPattern.MatchString(instanceID) {
		return nil, errors.New("Agent instance ID must be a UUID")
	}

	pending, err := s.loadPending()
	if err != nil {
		return nil, err
	}
	if pending == nil {
		if len(inputs) == 0 {
			return nil, nil
		}
		pending, err = s.buildPending(instanceID, inputs)
		if err != nil {
			return nil, err
		}
		if pending == nil {
			return nil, nil
		}
		if err := s.savePending(*pending); err != nil {
			return nil, err
		}
	}

	for _, record := range pending.Batch.Records {
		encodedRecord, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encode pending telemetry record: %w", err)
		}
		if len(encodedRecord) > MaximumRecordBytes {
			return s.quarantinedSourcesOrAdvance(pending, http.StatusRequestEntityTooLarge)
		}
	}

	body, err := json.Marshal(pending.Batch)
	if err != nil {
		return nil, fmt.Errorf("encode pending telemetry batch: %w", err)
	}
	if len(body) > MaximumBatchBytes {
		if len(pending.Batch.Records) == 1 {
			return s.quarantinedSourcesOrAdvance(pending, http.StatusRequestEntityTooLarge)
		}
		if err := s.splitPending(*pending); err != nil {
			return nil, fmt.Errorf("persist split telemetry batches: %w", err)
		}
		return nil, nil
	}

	for attempt := 0; attempt < 4; attempt++ {
		requestID, err := newUUID()
		if err != nil {
			return nil, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+EndpointPath, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("create telemetry request: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+credential)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-NADI-Agent-ID", agentID)
		request.Header.Set("X-NADI-Request-ID", requestID)

		response, requestErr := s.client.Do(request)
		if requestErr != nil {
			if attempt == 3 {
				return nil, fmt.Errorf("send telemetry batch after bounded retries: %w", requestErr)
			}
			if err := waitRetry(ctx, exponentialBackoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}

		responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
		response.Body.Close()
		if readErr != nil || len(responseBody) > 64*1024 {
			return nil, errors.New("Central telemetry response is unreadable or oversized")
		}

		switch response.StatusCode {
		case http.StatusOK:
			var ack Ack
			if err := json.Unmarshal(responseBody, &ack); err != nil {
				return nil, fmt.Errorf("decode Central telemetry acknowledgement: %w", err)
			}
			if !ack.Success || !ack.Data.Success || ack.Data.Status != "accepted" || ack.Data.BatchID != pending.Batch.BatchID || ack.Data.RejectedCount != 0 {
				return nil, errors.New("Central telemetry acknowledgement did not confirm acceptance of the pending batch")
			}
			if ack.Data.RecordCount != len(pending.Batch.Records) || ack.Data.AcceptedCount+ack.Data.DuplicateCount != len(pending.Batch.Records) {
				return nil, errors.New("Central telemetry acknowledgement counts do not match the pending batch")
			}
			return s.acknowledgedSourcesOrAdvance(pending)

		case http.StatusForbidden, http.StatusConflict, http.StatusGone, http.StatusUnprocessableEntity:
			return s.quarantinedSourcesOrAdvance(pending, response.StatusCode)

		case http.StatusRequestEntityTooLarge:
			if len(pending.Batch.Records) == 1 {
				return s.quarantinedSourcesOrAdvance(pending, response.StatusCode)
			}
			if err := s.splitPending(*pending); err != nil {
				return nil, fmt.Errorf("persist split telemetry batches after HTTP 413: %w", err)
			}
			return nil, nil

		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			if attempt == 3 {
				return nil, &HTTPStatusError{
					StatusCode: response.StatusCode,
					Message:    "bounded retry limit reached; pending batch retained",
				}
			}
			delay := exponentialBackoff(attempt)
			if response.StatusCode == http.StatusTooManyRequests {
				if retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now()); retryAfter > delay {
					delay = retryAfter
				}
			}
			if err := waitRetry(ctx, delay); err != nil {
				return nil, err
			}

		default:
			return nil, &HTTPStatusError{
				StatusCode: response.StatusCode,
				Message:    strings.TrimSpace(string(responseBody)),
			}
		}
	}

	return nil, errors.New("telemetry delivery ended without a result")
}
func (s *Sender) Complete() error {
	pending, err := s.loadPending()
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}
	if len(pending.Following) == 0 {
		return s.removePending()
	}

	next := pending.Following[0]
	next.Following = append([]pendingBatch(nil), pending.Following[1:]...)
	candidates := mergeSources(pending.CompletedSources, pending.Sources)
	remaining := append([]pendingBatch{next}, next.Following...)
	next.CompletedSources = sourcesStillPending(candidates, remaining)
	return s.savePending(next)
}

func (s *Sender) PendingSources() ([]Source, bool, error) {
	pending, err := s.loadPending()
	if err != nil {
		return nil, false, err
	}
	if pending == nil {
		return nil, false, nil
	}

	sources := mergeSources(pending.Sources, flattenFollowingDeliverySources(pending.Following))
	return sources, true, nil
}

func (s *Sender) DiscardPending() error {
	pending, err := s.loadPending()
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}

	for _, batch := range flattenPendingBatches(*pending) {
		entry := QuarantineEntry{
			QuarantinedAt: time.Now().UTC(),
			StatusCode:    0,
			Reason:        "local Activation Gate closed; pending telemetry retained in quarantine",
			Pending:       batch,
		}
		if err := s.appendQuarantine(entry); err != nil {
			return fmt.Errorf("quarantine pending telemetry while Activation Gate is closed: %w", err)
		}
	}

	return s.removePending()
}

func (s *Sender) buildPending(instanceID string, inputs []InputRecord) (*pendingBatch, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	sequences, err := s.loadSequences()
	if err != nil {
		return nil, err
	}
	batchID, err := newUUID()
	if err != nil {
		return nil, err
	}

	batch := Batch{
		ProtocolVersion: "1.0",
		BatchID:         batchID,
		AgentInstanceID: instanceID,
		SentAt:          time.Now().UTC(),
		Records:         make([]Record, 0, min(len(inputs), MaximumBatchRecords)),
	}
	sources := make([]Source, 0, cap(batch.Records))
	scopeKey := ""

	for index, input := range inputs {
		if index >= MaximumBatchRecords {
			break
		}
		if _, supported := RequiredCapability(input.Stream); !supported {
			return nil, fmt.Errorf("unsupported Central telemetry stream %q", input.Stream)
		}
		if len(input.Data) == 0 || !json.Valid(input.Data) {
			return nil, errors.New("telemetry input contains invalid data JSON")
		}
		if input.MetricSet != nil && len(*input.MetricSet) > 100 {
			return nil, errors.New("telemetry metric_set exceeds 100 characters")
		}
		if input.Source.EventID == "" {
			return nil, errors.New("telemetry source event_id must not be empty")
		}

		currentScope := "server"
		if IsServerStream(input.Stream) {
			if input.ApplicationID != nil {
				return nil, fmt.Errorf("server stream %s must not contain application_id", input.Stream)
			}
			if input.Source.Kind != "server" || input.Source.ApplicationID != "" {
				return nil, fmt.Errorf("server stream %s has an invalid local source scope", input.Stream)
			}
		} else {
			if input.ApplicationID == nil || !uuidPattern.MatchString(*input.ApplicationID) {
				return nil, fmt.Errorf("application stream %s requires a valid application_id UUID", input.Stream)
			}
			if input.Source.Kind != "application" || input.Source.ApplicationID != *input.ApplicationID {
				return nil, fmt.Errorf("application stream %s source does not match application_id", input.Stream)
			}
			currentScope = *input.ApplicationID
		}

		if scopeKey == "" {
			scopeKey = currentScope
		} else if scopeKey != currentScope {
			break
		}

		sequenceKey := currentScope + "|" + input.Stream
		nextSequence := sequences.Values[sequenceKey] + 1
		observedAt := input.ObservedAt.UTC()
		collectedAt := input.CollectedAt.UTC()
		if observedAt.IsZero() {
			observedAt = collectedAt
		}
		if collectedAt.IsZero() {
			collectedAt = time.Now().UTC()
		}

		recordID, err := newUUID()
		if err != nil {
			return nil, err
		}
		record := Record{
			RecordID:      recordID,
			Stream:        input.Stream,
			Sequence:      nextSequence,
			ObservedAt:    observedAt,
			CollectedAt:   collectedAt,
			ApplicationID: input.ApplicationID,
			MetricSet:     input.MetricSet,
			Data:          append(json.RawMessage(nil), input.Data...),
		}

		encodedRecord, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("encode telemetry record: %w", err)
		}
		if len(encodedRecord) > MaximumRecordBytes && len(batch.Records) > 0 {
			break
		}

		candidate := batch
		candidate.Records = append(append([]Record(nil), batch.Records...), record)
		encodedBatch, err := json.Marshal(candidate)
		if err != nil {
			return nil, fmt.Errorf("encode telemetry batch: %w", err)
		}
		if len(encodedBatch) > MaximumBatchBytes && len(batch.Records) > 0 {
			break
		}

		batch.Records = candidate.Records
		source := input.Source
		source.Stream = input.Stream
		sources = append(sources, source)
		sequences.Values[sequenceKey] = nextSequence

		if len(encodedRecord) > MaximumRecordBytes || len(encodedBatch) > MaximumBatchBytes {
			break
		}
	}

	if len(batch.Records) == 0 {
		return nil, nil
	}
	if err := s.saveSequences(sequences); err != nil {
		return nil, err
	}
	return &pendingBatch{Batch: batch, Sources: sources}, nil
}

func (s *Sender) splitPending(pending pendingBatch) error {
	middle := len(pending.Batch.Records) / 2
	if middle <= 0 || middle >= len(pending.Batch.Records) {
		return errors.New("telemetry batch cannot be split")
	}

	leftID, err := newUUID()
	if err != nil {
		return err
	}
	rightID, err := newUUID()
	if err != nil {
		return err
	}

	left := pendingBatch{
		CompletedSources: append([]Source(nil), pending.CompletedSources...),
		Batch: Batch{
			ProtocolVersion: pending.Batch.ProtocolVersion,
			BatchID:         leftID,
			AgentInstanceID: pending.Batch.AgentInstanceID,
			SentAt:          time.Now().UTC(),
			Records:         append([]Record(nil), pending.Batch.Records[:middle]...),
		},
		Sources: append([]Source(nil), pending.Sources[:middle]...),
	}
	right := pendingBatch{
		Batch: Batch{
			ProtocolVersion: pending.Batch.ProtocolVersion,
			BatchID:         rightID,
			AgentInstanceID: pending.Batch.AgentInstanceID,
			SentAt:          time.Now().UTC(),
			Records:         append([]Record(nil), pending.Batch.Records[middle:]...),
		},
		Sources: append([]Source(nil), pending.Sources[middle:]...),
	}
	left.Following = append([]pendingBatch{right}, pending.Following...)
	return s.savePending(left)
}

func (s *Sender) quarantinePending(statusCode int, reason string) error {
	pending, err := s.loadPending()
	if err != nil {
		return err
	}
	if pending == nil {
		return nil
	}

	quarantinedSources := markQuarantined(pending.Sources, statusCode)
	entryPending := *pending
	entryPending.Sources = quarantinedSources
	entryPending.Following = nil
	entry := QuarantineEntry{
		QuarantinedAt: time.Now().UTC(),
		StatusCode:    statusCode,
		Reason:        reason,
		Pending:       entryPending,
	}
	if err := s.appendQuarantine(entry); err != nil {
		return err
	}

	pending.Sources = quarantinedSources
	return s.savePending(*pending)
}

func (s *Sender) appendQuarantine(entry QuarantineEntry) error {
	content, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode telemetry quarantine entry: %w", err)
	}
	content = append(content, '\n')

	path := filepath.Join(s.dir, "quarantine.ndjson")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open telemetry quarantine file: %w", err)
	}
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return fmt.Errorf("secure telemetry quarantine file: %w", err)
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return fmt.Errorf("write telemetry quarantine entry: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync telemetry quarantine entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close telemetry quarantine file: %w", err)
	}
	if err := syncDirectory(s.dir); err != nil {
		return fmt.Errorf("sync telemetry quarantine directory: %w", err)
	}
	return nil
}

func flattenPendingBatches(pending pendingBatch) []pendingBatch {
	current := pending
	current.Following = nil
	result := []pendingBatch{current}
	for _, following := range pending.Following {
		result = append(result, flattenPendingBatches(following)...)
	}
	return result
}

func (s *Sender) acknowledgedSourcesOrAdvance(pending *pendingBatch) ([]Source, error) {
	sources := acknowledgeableSources(
		mergeSources(pending.CompletedSources, pending.Sources),
		pending.Following,
	)
	if len(sources) == 0 && len(pending.Following) > 0 {
		if err := s.Complete(); err != nil {
			return nil, fmt.Errorf("advance acknowledged split batch: %w", err)
		}
		return nil, nil
	}
	return sources, nil
}

func (s *Sender) quarantinedSourcesOrAdvance(pending *pendingBatch, statusCode int) ([]Source, error) {
	if err := s.quarantinePending(statusCode, fmt.Sprintf("Central rejected telemetry with HTTP %d", statusCode)); err != nil {
		return nil, fmt.Errorf("persist telemetry quarantine: %w", err)
	}

	updated, err := s.loadPending()
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, errors.New("quarantined telemetry pending state disappeared")
	}

	sources := acknowledgeableSources(
		mergeSources(updated.CompletedSources, updated.Sources),
		updated.Following,
	)
	if len(sources) == 0 && len(updated.Following) > 0 {
		if err := s.Complete(); err != nil {
			return nil, fmt.Errorf("advance quarantined split batch: %w", err)
		}
		if statusCode == http.StatusGone {
			return nil, &HTTPStatusError{StatusCode: statusCode, Message: "scope rejected; Control Poll must refresh"}
		}
		return nil, nil
	}
	return sources, nil
}

func flattenFollowingSources(following []pendingBatch) []Source {
	var sources []Source
	for _, pending := range following {
		sources = mergeSources(sources, pending.CompletedSources)
		sources = mergeSources(sources, pending.Sources)
		sources = mergeSources(sources, flattenFollowingSources(pending.Following))
	}
	return sources
}

func sourceEventKey(source Source) string {
	return source.Kind + "|" + source.ApplicationID + "|" + source.EventID
}

func sourceRecordKey(source Source) string {
	return sourceEventKey(source) + "|" + source.Stream
}


func flattenFollowingDeliverySources(following []pendingBatch) []Source {
	var sources []Source
	for _, pending := range following {
		sources = mergeSources(sources, pending.Sources)
		sources = mergeSources(sources, flattenFollowingDeliverySources(pending.Following))
	}
	return sources
}

func mergeSources(groups ...[]Source) []Source {
	merged := make([]Source, 0)
	indices := make(map[string]int)
	for _, group := range groups {
		for _, source := range group {
			key := sourceRecordKey(source)
			if index, found := indices[key]; found {
				if source.Quarantined {
					merged[index].Quarantined = true
					merged[index].QuarantineStatus = source.QuarantineStatus
				}
				continue
			}
			indices[key] = len(merged)
			merged = append(merged, source)
		}
	}
	return merged
}

func sourcesStillPending(candidates []Source, following []pendingBatch) []Source {
	if len(candidates) == 0 {
		return nil
	}
	future := make(map[string]struct{})
	addSourcesToSet(future, flattenFollowingSources(following))

	result := make([]Source, 0, len(candidates))
	for _, source := range candidates {
		if _, found := future[sourceEventKey(source)]; found {
			result = append(result, source)
		}
	}
	return mergeSources(result)
}

func acknowledgeableSources(candidates []Source, following []pendingBatch) []Source {
	if len(candidates) == 0 {
		return nil
	}
	future := make(map[string]struct{})
	addSourcesToSet(future, flattenFollowingSources(following))

	result := make([]Source, 0, len(candidates))
	for _, source := range candidates {
		if _, found := future[sourceEventKey(source)]; !found {
			result = append(result, source)
		}
	}
	return mergeAcknowledgedSources(result)
}

func mergeAcknowledgedSources(sources []Source) []Source {
	merged := make([]Source, 0)
	indices := make(map[string]int)
	for _, source := range sources {
		key := sourceEventKey(source)
		if index, found := indices[key]; found {
			if source.Quarantined {
				merged[index].Quarantined = true
				merged[index].QuarantineStatus = source.QuarantineStatus
			}
			continue
		}
		indices[key] = len(merged)
		merged = append(merged, source)
	}
	return merged
}

func addSourcesToSet(target map[string]struct{}, sources []Source) {
	for _, source := range sources {
		target[sourceEventKey(source)] = struct{}{}
	}
}

func markQuarantined(sources []Source, statusCode int) []Source {
	result := append([]Source(nil), sources...)
	for index := range result {
		result[index].Quarantined = true
		result[index].QuarantineStatus = statusCode
	}
	return result
}

func exponentialBackoff(attempt int) time.Duration {
	delay := time.Second * time.Duration(1<<attempt)
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return time.Duration(float64(delay) * (0.5 + mathrand.Float64()))
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		delay := time.Duration(seconds) * time.Second
		if delay > 5*time.Minute {
			return 5 * time.Minute
		}
		return delay
	}
	if parsed, err := http.ParseTime(value); err == nil {
		delay := parsed.Sub(now)
		if delay < 0 {
			return 0
		}
		if delay > 5*time.Minute {
			return 5 * time.Minute
		}
		return delay
	}
	return 0
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Sender) loadPending() (*pendingBatch, error) {
	content, err := os.ReadFile(filepath.Join(s.dir, "pending-batch.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read pending telemetry batch: %w", err)
	}
	var pending pendingBatch
	if err := json.Unmarshal(content, &pending); err != nil {
		return nil, fmt.Errorf("decode pending telemetry batch: %w", err)
	}
	return &pending, nil
}

func (s *Sender) savePending(pending pendingBatch) error {
	return s.writeJSON("pending-batch.json", pending)
}

func (s *Sender) removePending() error {
	path := filepath.Join(s.dir, "pending-batch.json")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove acknowledged telemetry batch: %w", err)
	}
	return syncDirectory(s.dir)
}

func (s *Sender) loadSequences() (sequenceState, error) {
	content, err := os.ReadFile(filepath.Join(s.dir, "sequences.json"))
	if errors.Is(err, os.ErrNotExist) {
		return sequenceState{Values: make(map[string]uint64)}, nil
	}
	if err != nil {
		return sequenceState{}, fmt.Errorf("read telemetry sequences: %w", err)
	}
	var current sequenceState
	if err := json.Unmarshal(content, &current); err != nil {
		return sequenceState{}, fmt.Errorf("decode telemetry sequences: %w", err)
	}
	if current.Values == nil {
		current.Values = make(map[string]uint64)
	}
	return current, nil
}

func (s *Sender) saveSequences(current sequenceState) error {
	return s.writeJSON("sequences.json", current)
}

func (s *Sender) writeJSON(name string, value any) error {
	content, err := json.MarshalIndent(value, "", "    ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	content = append(content, '\n')
	temporary, err := os.CreateTemp(s.dir, ".telemetry-*.tmp")
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.dir, name)); err != nil {
		return fmt.Errorf("replace %s: %w", name, err)
	}
	return syncDirectory(s.dir)
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate telemetry UUID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}
