# Nginx Error Log Collection Contract

Status: proposed Agent-side contract; not yet enabled in the runtime or accepted
by NADI Central.

## Capability

Use the exact Activation Grant capability:

- `system_logs`: permits server-level system log collection, including Nginx
  error-log metadata.

This capability is separate from `server_metrics`. A grant containing only
`server_metrics` must never authorize log access.

Laravel application logs remain a separate application-scoped capability:

- `application_logs`: permits the Bridge's redacted Laravel application error
  summary endpoint for that enrolled application.

Both names are proposed contract values. Central must issue them in signed
Activation Grants before their respective collectors can run.

## Stream

Use the existing telemetry stream name:

- `nginx_error_logs`

The stream is server-scoped. Its telemetry record must omit `application_id`.

## Payload schema

Version 1 payload:

```json
{
    "schema_version": 1,
    "status": "available",
    "collected_at": "2026-11-23T08:00:00Z",
    "entries": [
        {
            "timestamp": "2026-11-23T07:59:58Z",
            "level": "error",
            "fingerprint": "64-character-lowercase-sha256"
        }
    ]
}
```

Allowed statuses:

- `available`
- `disabled`
- `unavailable`

Allowed entry levels:

- `emerg`
- `alert`
- `crit`
- `error`

No raw log message, request URI, query string, IP address, hostname, upstream
address, header, cookie, credential, or stack trace is part of the payload.
The fingerprint is SHA-256 over a normalized message after removing quoted
values, common secret assignments, and IP/address tokens.

## Collection boundaries

- Collection is disabled unless an administrator explicitly configures an
  absolute Nginx error-log path.
- The Agent must not change Nginx configuration, ownership, group membership,
  ACLs, or file permissions.
- The collector must never request broad `adm` group membership.
- The Agent runs as the non-root `nadi-agent` user. If the configured file is
  not readable by that user, report `permission_denied` and fail closed.
- Only regular files are accepted. Symlink paths and files are rejected.
- Maximum read window defaults to 1 MiB and cannot exceed 4 MiB.
- Maximum emitted entries defaults to 100 and cannot exceed 500.
- Only error-severity entries are emitted.
- Collection and telemetry delivery must both require a currently valid,
  acknowledged Activation Grant containing `system_logs`.
- When the capability is absent, expired, revoked, or the application/server
  gate closes, collection stops and pending log records are cleared.

## Rollout

This contract is not yet wired into the Agent runtime. The next implementation
step must add a dedicated bounded log spool and a capability-specific runtime
gate, then validate the stream payload against Central's telemetry ingestion
contract. Do not enable or publish the feature before those checks pass.
