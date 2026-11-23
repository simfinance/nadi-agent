# Root-Owned Provisioning Helper Checkpoint

Status: implementation in progress. The root-owned helper is not implemented or production-ready.

## Current Agent baseline

The current Agent PR branch contains:

- Control Poll and the signed Activation Grant Runtime Activation Gate.
- Agent-to-Broker credential and activation-state handoff client.
- Root-owned local handoff broker with peer UID validation and bounded request handling.
- Broker mapping schema and systemd source unit.
- An independent release-manifest verifier foundation.
- An opt-in CLI output containing only non-secret enrollment identity metadata. The output excludes Agent and application credentials and is intended for the provisioning helper; it does not expose or copy state.json.

## Actual Bridge-to-helper request

The Bridge PrivilegedProvisioner currently sends this protocol version 1 shape:

    {
        "protocol_version": 1,
        "operation": "install_agent",
        "release": {
            "manifest_base64": "<exact signed manifest bytes>",
            "signature_base64": "<detached Ed25519 signature>",
            "artifact_path": "<private staging file path>"
        },
        "application": {
            "base_path": "<canonical Laravel application path>",
            "manifest_base64": "<base64 JSON application enrollment manifest>",
            "runtime_uid": 33,
            "runtime_gid": 33
        },
        "enrollment_token": "<one-time enrollment token>"
    }

The helper must validate this exact request shape. The existing installer boundary document still contains an older application object shape and must be reconciled before the protocol is frozen.

## Enrollment lifecycle constraint

The current Central enrollment endpoint creates one Agent and the application registrations supplied in the same enrollment request. The enrollment service rejects an already registered Agent instance. Replaying a consumed token is accepted only for the exact same request ID, Agent instance ID, and payload hash. The current API routes do not expose a separate application-registration endpoint.

Consequences:

- A helper cannot safely treat each Laravel Bridge installation as an independent enrollment for the same Agent.
- All applications intended for one Agent must be included in the initial enrollment request unless the Central API contract changes.
- The current Bridge EnrollmentManifestBuilder creates exactly one application entry.
- The current helper request carries one Laravel base path and one PHP-FPM UID/GID pair, so it cannot yet build secure per-application mappings for a multi-application host.

No Central changes are in scope for this checkpoint.

## PHP-FPM identity and credential isolation constraint

The Bridge preflight currently proceeds only when all discovered PHP-FPM pools resolve to the same non-root UID/GID pair. The broker stores each application credential as runtime_uid:runtime_gid with mode 0600.

If multiple Laravel applications run under the same PHP-FPM UID, a process compromised in one application can read another application's credential file whenever the filesystem path is traversable. Mode 0600 does not isolate processes that share the file owner UID. The broker's systemd ReadWritePaths limits broker writes; it does not prevent same-UID PHP processes from reading those files.

Therefore, a multi-application installation cannot claim OS-level per-application credential isolation while every application shares www-data as its PHP-FPM UID. A secure per-application model requires distinct runtime UIDs (and corresponding pool identification) or an explicitly accepted shared trust boundary.

## Required decision before completing the helper

The current safe direction, without changing Central, is:

1. Include all applications for one Agent in the initial enrollment manifest.
2. Resolve and validate each application's actual PHP-FPM pool identity independently.
3. Require a distinct non-root runtime UID per application if per-application credential isolation is required.
4. Generate broker mappings and exact systemd ReadWritePaths entries only from the validated per-application records.
5. Run enrollment as nadi-agent, consume only the new non-secret enrollment summary, and never parse or return state.json.
6. Preserve the local Agent state after a successful Central enrollment even if later local provisioning fails. Central enrollment is not reversible by local filesystem rollback.
7. Start only the control-plane Agent service after post-install checks. Monitoring remains blocked by the existing Central approval, signed-grant, and acknowledgement gate.

Until the application inventory and PHP-FPM identity model are settled, implementing the root helper as if one Bridge request represented a complete, isolated multi-application installation would encode an unsafe or incomplete contract.
