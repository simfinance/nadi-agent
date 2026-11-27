package control

import (
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
)

const maxCommandAcknowledgementResponse = 64 << 10

func (c *Client) AcknowledgeCommand(ctx context.Context, commandID string) error {
    if strings.TrimSpace(c.Token) == "" {
        return errors.New("agent bearer credential is not configured")
    }

    if strings.TrimSpace(commandID) == "" {
        return errors.New("command ID must not be empty")
    }

    endpoint := strings.TrimRight(c.BaseURL, "/") +
        "/api/v1/nadi/agent/commands/" + url.PathEscape(commandID) + "/ack"

    request, err := http.NewRequestWithContext(
        ctx,
        http.MethodPost,
        endpoint,
        bytes.NewReader([]byte("{}")),
    )
    if err != nil {
        return fmt.Errorf("create command receipt acknowledgement request: %w", err)
    }

    request.Header.Set("Accept", "application/json")
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Authorization", "Bearer "+c.Token)

    response, err := c.HTTP.Do(request)
    if err != nil {
        return fmt.Errorf("send command receipt acknowledgement: %w", err)
    }
    defer response.Body.Close()

    body, err := io.ReadAll(
        io.LimitReader(response.Body, maxCommandAcknowledgementResponse+1),
    )
    if err != nil {
        return fmt.Errorf("read command receipt acknowledgement response: %w", err)
    }

    if len(body) > maxCommandAcknowledgementResponse {
        return fmt.Errorf(
            "command receipt acknowledgement response exceeds %d bytes",
            maxCommandAcknowledgementResponse,
        )
    }

    if response.StatusCode != http.StatusOK {
        message := strings.TrimSpace(string(body))
        if len(message) > 512 {
            message = message[:512]
        }

        return fmt.Errorf(
            "Central command receipt acknowledgement returned HTTP %d: %s",
            response.StatusCode,
            message,
        )
    }

    var envelope struct {
        Success      bool   `json:"success"`
        Acknowledged bool   `json:"acknowledged"`
        CommandID    string `json:"command_id"`
    }

    if err := json.Unmarshal(body, &envelope); err != nil {
        return fmt.Errorf("decode command receipt acknowledgement response: %w", err)
    }

    if !envelope.Success || !envelope.Acknowledged {
        return errors.New("Central did not confirm command receipt acknowledgement")
    }

    if envelope.CommandID != "" && envelope.CommandID != commandID {
        return errors.New("Central command receipt acknowledgement identity mismatch")
    }

    return nil
}
