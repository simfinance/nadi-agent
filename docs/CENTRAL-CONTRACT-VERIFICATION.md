# NADI Central Contract Verification

Reviewed against the read-only `main` branch of `simfinance/nadi-central` on 2026-11-23.

No Central files, branches, pull requests, workflows, or deployment state were modified.

## Enrollment contract

Central exposes `POST /api/v1/nadi/agent/enroll` with a rate limit of 10 requests per minute.

The controller requires this request structure:

- `enrollment_token`: exactly 76 characters.
- `request_id`: UUID.
- `server`: object containing required `hostname`; `ip_address`, `os_name`, `os_version`, and `architecture` are optional.
- `agent`: object containing `agent_instance_id` (UUID), `agent_version`, and `protocol_version`.
- `applications`: array containing 1–20 entries.
- Each application requires a distinct `application_key`, `application_name`, `environment`, and `base_url`. Framework and PHP versions are optional.

The enrollment service additionally enforces HTTPS application URLs, enrollment-token environment scope, global application-key uniqueness, and uniqueness of `agent_instance_id`.

One successful enrollment transaction creates:

1. One server record.
2. One Agent record associated with that server.
3. One Agent credential.
4. One application record, endpoint, registration record, and application credential for each submitted application.

Every application is attached to the same Agent. The initial application state is registration `pending`, activation `pending`, and monitoring `dormant`. Central stores the endpoint as the submitted base URL and returns it with the `/_nadi/v1` prefix.

A consumed enrollment token can only replay the exact original request (same request ID, Agent instance ID, and normalized payload hash). Central rejects a different request using that token and rejects a previously registered Agent instance. There is no append-applications endpoint in the inspected API routes.

**Agent implementation rule:** submit all applications for one server in one enrollment request. Do not split applications across enrollment calls and do not retry a changed payload with a consumed token.

## Enrollment response

A successful response contains:

- `data.server_id`, `data.agent_id`, and `data.agent_instance_id`.
- `data.agent_status` and one `data.agent_credential`.
- `data.agent_credential_expires_at`.
- `data.control.poll_url` and `poll_interval_seconds`.
- `data.applications[]`, with Central application ID/key/name/environment, registration ID and statuses, endpoint URL, and one `application_credential` per application.

The Agent persists the Agent credential and application credentials in its protected state. The Agent must not print or include either credential in its enrollment summary. The summary used by provisioning contains identity metadata only.

## Control Poll and activation

Authenticated Agent Control Poll is `POST /api/v1/nadi/agent/control/poll`. The current controller returns:

- Agent identity/status and `installation_state`.
- `control.poll_interval_seconds` (currently 30).
- One entry per application, including registration, activation, and monitoring status.
- `endpoint` as a URL string (the Agent decoder also retains compatibility with an endpoint object).
- `monitoring_enabled` and an optional signed `activation_grant`.
- A commands array and server timestamp.

Central only selects a grant when the Agent is installed, registration is approved, activation is pending/active, monitoring is not suspended, and an active, unexpired, unrevoked grant passes Central's identity and signature checks.

The Agent must independently verify the signed grant and its Agent/server/application/registration identity, persist it, and acknowledge it through:

`POST /api/v1/nadi/agent/activation-grants/{grantId}/ack`

The acknowledgement requires `request_id` UUID, `application_id` UUID, and `result` equal to `success` or `failed`. A failed result requires `error_code`; `message` is optional. Central changes application activation/monitoring state only after processing this acknowledgement. The Agent's monitoring gate therefore remains closed until grant verification and successful acknowledgement are complete.

## Release verification

Central exposes `GET /api/v1/nadi/releases/manifest` and returns the detached Ed25519 signature in `X-NADI-Manifest-Signature`.

The inspected controller currently publishes:

- Product `nadi-agent`, schema version 1.
- Key ID `nadi-agent-release-2026-01`.
- Linux AMD64 and ARM64 artifacts.
- Version `0.7.5-dev` at the time of review.

The Agent's embedded release verifier uses the same release key ID. The activation key ID configured by Central is `nadi-central-2026-01`; the Agent service configuration uses that same ID.

## Agent-side alignment made in this change set

- Agent enrollment request generation now treats server IPv4 as optional, consistent with Central's nullable `server.ip_address` validation. If the host has no unambiguous usable IPv4 address, enrollment continues without that field.
- Control Poll test fixture now uses Central's actual string-valued `endpoint` response and asserts that the Agent decodes it.
- The existing multi-application enrollment request, per-application credential persistence, Activation Grant verification/acknowledgement, and Bridge credential handoff remain the Agent-side mechanisms used with this Central contract.

## Central source files reviewed

- [README.md](https://github.com/simfinance/nadi-central/blob/main/README.md)
- [routes/api.php](https://github.com/simfinance/nadi-central/blob/main/routes/api.php)
- [AgentEnrollmentController.php](https://github.com/simfinance/nadi-central/blob/main/app/Http/Controllers/Api/V1/Nadi/AgentEnrollmentController.php)
- [EnrollmentService.php](https://github.com/simfinance/nadi-central/blob/main/app/Services/Agent/EnrollmentService.php)
- [NadiAgent.php](https://github.com/simfinance/nadi-central/blob/main/app/Models/NadiAgent.php)
- [NadiApplication.php](https://github.com/simfinance/nadi-central/blob/main/app/Models/NadiApplication.php)
- [AgentControlController.php](https://github.com/simfinance/nadi-central/blob/main/app/Http/Controllers/Api/V1/Nadi/AgentControlController.php)
- [AgentActivationController.php](https://github.com/simfinance/nadi-central/blob/main/app/Http/Controllers/Api/V1/Nadi/AgentActivationController.php)
- [ActivationAcknowledgementService.php](https://github.com/simfinance/nadi-central/blob/main/app/Services/Activation/ActivationAcknowledgementService.php)
- [ReleaseManifestController.php](https://github.com/simfinance/nadi-central/blob/main/app/Http/Controllers/Api/V1/Nadi/ReleaseManifestController.php)

This document records source-level contract review only. It does not assert that the deployed Central environment has the same commit, secrets, database state, or operational configuration.
