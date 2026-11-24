# ADR-0002: Fixed Provisioning Helper Operation Lifecycle

- Status: Accepted
- Date: 2026-11-24
- Owners: NADI Agent and Laravel Bridge maintainers
- Scope: Agent/Bridge installer protocol only
- Central repository: Read-only; no Central API or schema changes

## Context

The current Bridge privileged provisioning contract contains incompatible requirements:

1. The protocol v1 `install_agent` example includes the one-time enrollment token.
2. The allowed-effects section says `install_agent` must not enroll the Agent.
3. The service lifecycle section requires a separate fixed operation for enabling and starting `nadi-agent.service`.
4. The Agent must be enrolled as the dedicated non-root `nadi-agent` user, with the token delivered through standard input.
5. Enrollment may consume a Central one-use token. A timeout or process failure after submission cannot be treated as a safe retry without an explicit Agent-confirmed replay state.

The current helper source prototype combines installation, enrollment, broker configuration, and service activation in one flow. It must not be released or wired into the customer installer until this contract is resolved.

## Proposed decision

Use three fixed operations through the existing exact helper invocation:

`/usr/bin/sudo -n -- /usr/libexec/nadi/nadi-provision --request-stdin`

The request envelope retains a strict protocol version and allows only the operation-specific fields below. The helper must reject unknown fields, duplicate keys, trailing JSON, oversized requests, unsupported versions, and any operation outside this allowlist.

### 1. `install_agent`

Allowed inputs:
- Exact signed release manifest bytes and detached signature.
- Staged artifact path.
- Complete 1–20 local application inventory, including canonical base paths and PHP-FPM runtime UID/GID mappings.

Allowed effects:
- Independently verify release signature, trusted key ID/fingerprint, architecture, artifact digest, canonical application paths, PHP-FPM identities, and non-root runtime identities.
- Create/validate the fixed `nadi-agent` system account and group.
- Create/validate the five canonical directories from Master Architecture section 10.4.
- Install the Agent binary, activation public key, and fixed systemd unit assets atomically.
- Write only non-secret, root-owned installer metadata required by later operations.
- Run `systemctl daemon-reload`.

Prohibited effects:
- Must not submit enrollment to Central.
- Must not handle or persist the one-time enrollment token.
- Must not publish Bridge credentials or activation state.
- Must not enable or start services.

Expected result:
- A fresh install returns `success=true`, `phase=installed`, `enrollment_status=not_started`, `retry_safe=true`.
- If a previous enrollment has a matching root-owned completion record and the same installed inventory/release, the operation may return `phase=enrolled`, `enrollment_status=registered`, `retry_safe=false` so the Artisan installer can resume at service activation without repeating enrollment.
- No secret material in the response.

### 2. `enroll_agent`

Allowed inputs:
- The complete signed-inventory application manifest.
- The one-time enrollment token, supplied only in the helper request standard input and forwarded to the Agent standard input.
- No arbitrary executable, destination path, user, group, or service name.

Allowed effects:
- Validate the manifest against the root-owned inventory installed by `install_agent`.
- Execute the fixed Agent binary as the dedicated `nadi-agent` UID/GID.
- Never place the token in argv, environment variables, logs, or response output.
- Consume only the Agent's bounded non-secret enrollment summary; never read, parse, display, return, or copy `state.json`.
- After confirmed registration, reconcile Central-issued application IDs to the local inventory and install the fixed broker mapping, per-application credential directories, and exact systemd broker write-path drop-in.
- Preserve Agent state and report a non-retryable partial outcome if Central registration succeeded but broker configuration failed.

Expected result:
- Success uses `phase=enrolled`, `enrollment_status=registered`, and `retry_safe=false`.
- A bounded success or partial-outcome envelope.
- A root-owned, non-secret enrollment-attempt marker is persisted before invoking Agent. If no verified completion record exists on a later invocation, the operation fails closed with `enrollment_status=unknown` and `retry_safe=false`.
- `retry_safe=false` whenever enrollment was submitted and the outcome is unknown or registered.
- A retry may be marked safe only when the Agent proves that no enrollment request was submitted, or proves that it will replay the exact persisted request.

### 3. `start_agent`

Allowed inputs:
- No caller-selected service, unit, path, or command.

Allowed effects:
- Verify the root-owned enrollment/broker completion metadata.
- Enable and start only `nadi-handoff-broker.service` and `nadi-agent.service`.
- Verify both known units are active.
- Do not start monitoring directly; the Agent Runtime Activation Gate remains authoritative.

Expected result:
- Success uses `phase=completed`, `enrollment_status=registered`, and `retry_safe=false`.
- Success only after both fixed services pass startup verification.
- A partial outcome must identify the phase without secrets and must never instruct an automatic enrollment retry.

## Bridge adapter sequence

The Bridge installer invokes the three fixed operations in order:

1. `install_agent`
2. `enroll_agent`
3. `start_agent`

It must stop immediately on a failed phase. On a repeated install, a verified existing enrollment may be reported by `install_agent`; the Bridge still invokes `enroll_agent`, which must return the matching verified completion idempotently, before calling `start_agent`. If enrollment has an unknown outcome without a verified completion record, the Bridge must display the bounded non-secret status and explicitly prohibit a fresh-token retry until local Agent state and Central registration are reconciled.

The Bridge adapter must not modify Laravel, PHP-FPM, Nginx, firewall, Supervisor, or client application configuration without the explicit configuration approval required by the Master Architecture.

## Rollback and recovery

- Before enrollment begins, rollback may remove only files/directories created by the current transaction and only when their content/ownership still matches the helper's own creation record.
- Never delete an existing Agent state file, existing valid Agent identity, or unrelated configuration.
- After enrollment may have reached Central, preserve Agent state and all evidence needed for repair. Do not roll back by deleting the identity or retrying enrollment.
- Existing valid Agent state must be restored/validated by the Agent binary itself; the helper must not inspect `state.json`.
- Invalid or unreadable state must fail closed and enter an explicit repair workflow.

## Consequences

Positive:
- Aligns helper behavior with the existing Bridge provisioning boundary.
- Separates privileged file installation, one-use enrollment, and service activation.
- Makes retry safety explicit and testable.
- Keeps Central read-only and preserves the non-root Agent runtime.

Costs:
- Requires operation-specific request/response schemas.
- Requires coordinated changes in Agent helper, Bridge adapter, tests, docs, and rollback handling.
- Requires explicit non-secret transaction metadata for safe phase transitions.

## Approval record

- Approved by the project owner in the NADI project conversation on 2026-11-24.
- Approval scope: implement the three fixed internal operations consistently across Agent and Laravel Bridge.
- Customer-facing installation remains exactly two commands: `composer require nadi/laravel-agent` followed by `php artisan nadi:install`.
- This approval does not waive the remaining implementation, rollback, trusted packaging, integration-test, or release gates. The helper must remain unavailable to production until those gates pass.
