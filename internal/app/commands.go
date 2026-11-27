package app

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "strings"
    "time"

    "nadi-agent/internal/control"
    "nadi-agent/internal/state"
)

const (
    maximumReceivedCommands = 500
    maximumCommandPayload   = 256 << 10
    maximumCommandInboxSize = 4 << 20
)

func (a *App) acceptCommands(
    ctx context.Context,
    store *state.Store,
    commands []control.Command,
) error {
    for _, command := range commands {
        received, err := validateReceivedCommand(command, time.Now().UTC())
        if err != nil {
            a.logger.Warn(
                "Central command rejected before durable acceptance",
                "command_id", command.CommandID,
                "error", err,
            )
            continue
        }

        current, err := store.Load()
        if err != nil {
            return fmt.Errorf("load Agent state before accepting command: %w", err)
        }

        existingIndex := -1
        for index := range current.ReceivedCommands {
            if current.ReceivedCommands[index].CommandID == received.CommandID {
                existingIndex = index
                break
            }
        }

        if existingIndex >= 0 {
            existing := current.ReceivedCommands[existingIndex]
            if !sameReceivedCommand(existing, received) {
                return fmt.Errorf(
                    "command ID %q was redelivered with different content",
                    received.CommandID,
                )
            }

            continue
        }

        if len(current.ReceivedCommands) >= maximumReceivedCommands {
            return fmt.Errorf(
                "durable command inbox reached its limit of %d records",
                maximumReceivedCommands,
            )
        }

        if commandInboxSize(current.ReceivedCommands)+len(received.Payload) >
            maximumCommandInboxSize {
            return fmt.Errorf(
                "durable command inbox would exceed %d bytes",
                maximumCommandInboxSize,
            )
        }

        current.ReceivedCommands = append(current.ReceivedCommands, received)
        if err := store.Save(current); err != nil {
            return fmt.Errorf(
                "persist command %q before receipt acknowledgement: %w",
                received.CommandID,
                err,
            )
        }
    }

    current, err := store.Load()
    if err != nil {
        return fmt.Errorf("reload Agent state before command receipt acknowledgement: %w", err)
    }

    return a.flushPendingCommandReceipts(ctx, store, &current)
}

func (a *App) flushPendingCommandReceipts(
    ctx context.Context,
    store *state.Store,
    current *state.State,
) error {
    for index := range current.ReceivedCommands {
        command := &current.ReceivedCommands[index]
        if command.Acknowledged {
            continue
        }

        if err := a.controlHTTP.AcknowledgeCommand(ctx, command.CommandID); err != nil {
            return fmt.Errorf(
                "acknowledge receipt for command %q: %w",
                command.CommandID,
                err,
            )
        }

        command.Acknowledged = true
        if err := store.Save(*current); err != nil {
            command.Acknowledged = false
            return fmt.Errorf(
                "persist receipt acknowledgement for command %q: %w",
                command.CommandID,
                err,
            )
        }

        a.logger.Info(
            "Central command receipt acknowledged; execution remains disabled",
            "command_id", command.CommandID,
            "application_id", command.ApplicationID,
            "command_type", command.CommandType,
        )
    }

    return nil
}

func validateReceivedCommand(
    command control.Command,
    now time.Time,
) (state.ReceivedCommand, error) {
    if strings.TrimSpace(command.CommandID) == "" || len(command.CommandID) > 128 {
        return state.ReceivedCommand{}, errors.New("command_id is empty or exceeds 128 characters")
    }

    if strings.TrimSpace(command.ApplicationID) == "" || len(command.ApplicationID) > 128 {
        return state.ReceivedCommand{}, errors.New("application_id is empty or exceeds 128 characters")
    }

    if strings.TrimSpace(command.CommandType) == "" || len(command.CommandType) > 64 {
        return state.ReceivedCommand{}, errors.New("command_type is empty or exceeds 64 characters")
    }

    if len(command.Payload) == 0 || len(command.Payload) > maximumCommandPayload ||
        !json.Valid(command.Payload) {
        return state.ReceivedCommand{}, errors.New("command payload is empty, oversized, or invalid JSON")
    }

    issuedAt, err := time.Parse(time.RFC3339Nano, command.IssuedAt)
    if err != nil {
        return state.ReceivedCommand{}, fmt.Errorf("command issued_at is invalid: %w", err)
    }

    received := state.ReceivedCommand{
        CommandID:     command.CommandID,
        ApplicationID: command.ApplicationID,
        CommandType:   command.CommandType,
        Payload:       append(json.RawMessage(nil), command.Payload...),
        IssuedAt:      issuedAt.UTC(),
        ReceivedAt:    now.UTC(),
    }

    if strings.TrimSpace(command.ExpiresAt) != "" {
        expiresAt, parseErr := time.Parse(time.RFC3339Nano, command.ExpiresAt)
        if parseErr != nil {
            return state.ReceivedCommand{}, fmt.Errorf("command expires_at is invalid: %w", parseErr)
        }

        if !expiresAt.After(now) {
            return state.ReceivedCommand{}, errors.New("command has expired")
        }

        expiresAt = expiresAt.UTC()
        received.ExpiresAt = &expiresAt
    }

    return received, nil
}

func sameReceivedCommand(
    existing state.ReceivedCommand,
    incoming state.ReceivedCommand,
) bool {
    if existing.CommandID != incoming.CommandID ||
        existing.ApplicationID != incoming.ApplicationID ||
        existing.CommandType != incoming.CommandType ||
        !existing.IssuedAt.Equal(incoming.IssuedAt) ||
        !bytes.Equal(bytes.TrimSpace(existing.Payload), bytes.TrimSpace(incoming.Payload)) {
        return false
    }

    if existing.ExpiresAt == nil || incoming.ExpiresAt == nil {
        return existing.ExpiresAt == nil && incoming.ExpiresAt == nil
    }

    return existing.ExpiresAt.Equal(*incoming.ExpiresAt)
}

func commandInboxSize(commands []state.ReceivedCommand) int {
    content, err := json.Marshal(commands)
    if err != nil {
        return maximumCommandInboxSize + 1
    }

    return len(content)
}
