# NADI Central v1.1 Log Telemetry Contract

Status: Agent-side schema normalization and Nginx collector output are implemented
in this branch. Runtime log delivery is not enabled or wired. Central log
ingestion must remain disabled until the Central deployment gate is explicitly
completed by its operator.

## Capability and scope

Use only the exact signed Activation Grant capabilities:

- `system_logs`: server-scoped Nginx error logs. The telemetry record omits
  `application_id`.
- `application_logs`: logs for one application. The record must contain that
  application's exact `application_id`; another application's grant cannot
  authorize it.

These capabilities are independent from `server_metrics` and
`application_metrics`. No capability substitutes for another.

## nginx_error_logs payload

Each record's `data` must contain exactly:

- `timestamp`: required RFC3339-compatible date/time string.
- `severity`: one of `emergency`, `alert`, `critical`, `error`,
  `warning`, `notice`, `info`, `debug`.
- `message`: required non-empty string, maximum 8,192 bytes.
- `source`: optional; when supplied it must equal `nginx`.

The Agent normalizes timestamps to UTC and maps Nginx severity aliases
`emerg`, `crit`, and `warn` to `emergency`, `critical`, and
`warning`. The collector emits the fixed source `nginx`.

## application_logs payload

Each record's `data` must contain exactly:

- `timestamp`: required RFC3339-compatible date/time string.
- `level`: one of the eight levels listed above.
- `channel`: required non-empty string, maximum 100 bytes.
- `message`: required non-empty string, maximum 8,192 bytes.
- `context`: optional object with at most 50 top-level fields.

Context strings are limited to 2,048 characters. Only scalar string, boolean,
number, and null context values are accepted. Nested objects and arrays are
rejected. Unknown top-level fields are rejected. Raw stack traces are rejected.

The Bridge endpoint `GET /_nadi/v1/logs/application` returns a sanitized
summary, not raw application log messages or stack traces. The Agent maps the
Bridge's `source` marker (`laravel_application`) to the Central `channel`
field, derives the required `message` from the returned exception type (or
uses an explicit unclassified-summary label), and carries the Bridge
fingerprint and exception type in `context`. The Agent does not reconstruct or
claim to possess the original raw log message.

The Agent's `internal/logtelemetry` normalizers redact common authorization,
Bearer, cookie, password, token, API-key, secret, and credential patterns.
Sensitive context keys are replaced with `[REDACTED]`.

**Redaction is best-effort, not exhaustive.** It cannot guarantee detection of
every secret or personally identifying value. The Agent must not claim that
all sensitive information is always detected.

## Collection and delivery boundaries

- The Nginx collector is still not wired into the Agent runtime or
  telemetry spool. Its output schema is prepared, but this branch does not
  start Nginx log collection or send Nginx log records.
- Application log summaries use the existing Laravel Bridge
  `GET /_nadi/v1/logs/application` endpoint. They are collected and mapped
  only when the exact `application_logs` grant is active and the Agent-local
  opt-in `NADI_AGENT_LOG_TELEMETRY_ENABLED=true` is explicitly configured.
  This opt-in defaults to `false`.
- Keep that opt-in disabled: the Bridge summary endpoint does not expose a
  durable cursor, and Agent-side persistent deduplication across polling and
  restart is not yet implemented. Enabling it before that work is complete
  could re-submit recent summary entries.
- The Bridge returns sanitized summary metadata, not raw log messages. The
  Agent derives the Central `message` field from the returned exception type;
  it does not invent raw log contents.
- A Bridge HTTP 501 marks the endpoint unsupported. The Agent does not
  synthesize application log events when the endpoint is unsupported.
- Queue and scheduler endpoints that return HTTP 501 remain unsupported; the
  Agent must not synthesize queue or scheduler telemetry.
- The collector remains read-only. It must not change Nginx configuration,
  ownership, groups, ACLs, file permissions, or service state.
- Only explicitly configured absolute paths are eligible. Symlink path
  components and non-regular files are rejected.
- The existing bounded read limits remain in force.
- Log streams must pass the same Activation Gate and exact capability checks
  as other telemetry. Server log records require at least one eligible
  acknowledged application grant on the same Agent with `system_logs`.
- Application log records require the exact application's eligible,
  acknowledged grant with `application_logs`.

## Central deployment gate

Do not change Central configuration from the Agent. Central must continue to
use `NADI_TELEMETRY_LOGS_ENABLED=false` until its operator has confirmed the
schema, redaction, capability enforcement, Central/Agent integration tests,
and non-production end-to-end validation.
