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

	for index := 0; index < len(inputs); {
		first := inputs[index]
		groupKey := inputSourceKey(first.Source)
		groupEnd := index + 1
		for groupEnd < len(inputs) && inputSourceKey(inputs[groupEnd].Source) == groupKey {
			groupEnd++
		}
		group := inputs[index:groupEnd]

		groupScope := "server"
		if first.ApplicationID != nil {
			groupScope = *first.ApplicationID
		}
		if scopeKey == "" {
			scopeKey = groupScope
		} else if scopeKey != groupScope {
			break
		}
		if len(batch.Records)+len(group) > MaximumBatchRecords {
			if len(batch.Records) == 0 {
				return nil, fmt.Errorf("one source event contains more than %d telemetry records", MaximumBatchRecords)
			}
			break
		}

		nextSequences := sequenceState{
			Values: make(map[string]uint64, len(sequences.Values)),
		}
		for key, value := range sequences.Values {
			nextSequences.Values[key] = value
		}

		groupRecords := make([]Record, 0, len(group))
		groupSources := make([]Source, 0, len(group))
		for _, input := range group {
			if _, supported := RequiredCapability(input.Stream); !supported {
				return nil, fmt.Errorf("unsupported Central telemetry stream %q", input.Stream)
			}
			if len(input.Data) == 0 || !json.Valid(input.Data) {
				return nil, errors.New("telemetry input contains invalid data JSON")
			}
			if input.MetricSet != nil && len(*input.MetricSet) > 100 {
				return nil, errors.New("telemetry metric_set exceeds 100 characters")
			}
			if input.Source.EventID == "" || input.Source.Kind == "" {
				return nil, errors.New("telemetry source kind and event_id are required")
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
			if currentScope != groupScope {
				return nil, errors.New("one source event cannot span telemetry scopes")
			}

			sequenceKey := currentScope + "|" + input.Stream
			nextSequence := nextSequences.Values[sequenceKey] + 1
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

			groupRecords = append(groupRecords, record)
			source := input.Source
			source.Stream = input.Stream
			groupSources = append(groupSources, source)
			nextSequences.Values[sequenceKey] = nextSequence
		}

		candidate := batch
		candidate.Records = append(append([]Record(nil), batch.Records...), groupRecords...)
		encodedBatch, err := json.Marshal(candidate)
		if err != nil {
			return nil, fmt.Errorf("encode telemetry batch: %w", err)
		}
		if len(encodedBatch) > MaximumBatchBytes && len(batch.Records) > 0 {
			break
		}

		batch.Records = candidate.Records
		sources = append(sources, groupSources...)
		sequences = nextSequences
		index = groupEnd

		if len(batch.Records) >= MaximumBatchRecords || len(encodedBatch) > MaximumBatchBytes {
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

func inputSourceKey(source Source) string {
	return source.Kind + "|" + source.ApplicationID + "|" + source.EventID
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
