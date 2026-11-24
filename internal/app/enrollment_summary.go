package app

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"

    "nadi-agent/internal/identity"
    "nadi-agent/internal/state"
)

type EnrollmentSummary struct {
    ProtocolVersion  int                            `json:"protocol_version"`
    EnrollmentStatus string                         `json:"enrollment_status"`
    AgentInstanceID  string                         `json:"agent_instance_id"`
    AgentID          string                         `json:"agent_id"`
    ServerID         string                         `json:"server_id"`
    Applications     []EnrollmentApplicationSummary `json:"applications"`
}

type EnrollmentApplicationSummary struct {
    ApplicationID   string `json:"application_id"`
    ApplicationKey  string `json:"application_key"`
    ApplicationName string `json:"application_name"`
    Environment     string `json:"environment"`
    RegistrationID  string `json:"registration_id"`
}

func (a *App) WriteEnrollmentSummary(writer io.Writer) error
{
    store, err := state.Open(a.config.StateDir)
    if err != nil
    {
        return fmt.Errorf("open Agent state for enrollment summary: %w", err)
    }
    defer store.Close()

    current, err := store.Load()
    if err != nil
    {
        return fmt.Errorf("load Agent state for enrollment summary: %w", err)
    }

    return writeEnrollmentSummary(writer, current)
}

func (a *App) WriteVerifiedEnrollmentSummary(writer io.Writer) error
{
    current, err := identity.VerifyReadOnly(a.config.StateDir)
    if err != nil
    {
        return fmt.Errorf("verify existing Agent identity: %w", err)
    }

    return writeEnrollmentSummary(writer, current)
}

func writeEnrollmentSummary(writer io.Writer, current state.State) error
{
    if current.EnrollmentStatus != "registered"
    {
        return errors.New("Agent enrollment is not registered")
    }

    if current.AgentInstanceID == "" || current.CentralAgentID == "" || current.CentralServerID == ""
    {
        return errors.New("Agent enrollment identity is incomplete")
    }

    if len(current.Applications) < 1 || len(current.Applications) > 20
    {
        return errors.New("Agent enrollment application count is invalid")
    }

    summary := EnrollmentSummary{
        ProtocolVersion:  1,
        EnrollmentStatus: current.EnrollmentStatus,
        AgentInstanceID:  current.AgentInstanceID,
        AgentID:          current.CentralAgentID,
        ServerID:         current.CentralServerID,
        Applications:     make([]EnrollmentApplicationSummary, 0, len(current.Applications)),
    }

    seenIDs := make(map[string]struct{}, len(current.Applications))
    seenKeys := make(map[string]struct{}, len(current.Applications))

    for index, application := range current.Applications
    {
        if application.ApplicationID == "" || application.ApplicationKey == "" || application.RegistrationID == ""
        {
            return fmt.Errorf("Agent enrollment application %d has incomplete identity", index)
        }

        if _, exists := seenIDs[application.ApplicationID]; exists
        {
            return errors.New("Agent enrollment contains duplicate application IDs")
        }

        if _, exists := seenKeys[application.ApplicationKey]; exists
        {
            return errors.New("Agent enrollment contains duplicate application keys")
        }

        seenIDs[application.ApplicationID] = struct{}{}
        seenKeys[application.ApplicationKey] = struct{}{}

        summary.Applications = append(summary.Applications, EnrollmentApplicationSummary{
            ApplicationID:   application.ApplicationID,
            ApplicationKey:  application.ApplicationKey,
            ApplicationName: application.ApplicationName,
            Environment:     application.Environment,
            RegistrationID:  application.RegistrationID,
        })
    }

    encoder := json.NewEncoder(writer)
    encoder.SetEscapeHTML(false)

    if err := encoder.Encode(summary); err != nil
    {
        return fmt.Errorf("write non-secret Agent enrollment summary: %w", err)
    }

    return nil
}
