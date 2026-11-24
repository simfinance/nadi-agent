# Root-Owned Provisioning Helper Checkpoint

Status: implementation in progress. The root-owned helper is not implemented or production-ready.

## Confirmed Central enrollment model

The NADI Central `main` source was inspected directly:

- `NadiAgent::applications()` is a `HasMany` relationship.
- `AgentEnrollmentController` accepts an `applications` array with 1–20 entries.
- `EnrollmentService` creates one server and one Agent, then creates every submitted application against that same Agent.
- A registered `agent_instance_id` is rejected on a new enrollment.
- A consumed enrollment token can only replay the exact original request; Central has no separate API endpoint to append applications to an existing Agent.

The implementation contract for this project is therefore:

**One server = one NADI Agent = one initial enrollment request containing all applications on that server.**

The maximum of 20 applications is the current Central API validation limit. The helper must not run a separate enrollment for each Laravel application and must not attempt to reuse a consumed token to append another application.

## Current Agent baseline

The current Agent PR branch contains:

- Control Poll and the signed Activation Grant Runtime Activation Gate.
- Agent-to-Broker credential and activation-state handoff client.
- Root-owned local handoff broker with peer UID validation and bounded request handling.
- The signed Agent binary can now run the broker through its fixed `--handoff-broker` mode, so the same verified release artifact can back the Agent and broker systemd services.
- A strict multi-application provisioning request decoder validates the 1–20 application mapping, enrollment manifest key correspondence, unique runtime UIDs, canonical non-overlapping paths, and bounded JSON.
- Broker mapping schema and systemd source unit.
- An independent release-manifest verifier foundation.
- An opt-in CLI output containing only non-secret enrollment identity metadata. The output excludes Agent and application credentials and is intended for the provisioning helper; it does not expose or copy state.json.

The Go enrollment manifest already supports 1–20 applications in a single request. The missing work is primarily the multi-application Bridge inventory, the root-owned helper, and their integration.

## Existing Bridge request and mismatch

The Bridge PR branch now sends one enrollment manifest plus an `applications[]` mapping for all local Laravel applications. Its CI run #54 passed. The helper request parser validates the same multi-application contract.

The target protocol must carry:

- One signed Agent release manifest, detached signature, and staged artifact path.
- One enrollment manifest containing all 1–20 application entries.
- An `applications` array containing one local mapping record per application: stable application key, canonical Laravel base path, runtime UID, and runtime GID.
- One one-time enrollment token for the entire Agent.
- No caller-selected commands, executable paths, service names, file modes, credential destinations, or arbitrary system paths.

The helper must verify that every mapping record corresponds to exactly one application key in the enrollment manifest. Duplicate keys, duplicate or overlapping application paths, unresolved runtime identities, and more than 20 applications must fail closed.

## PHP-FPM identity and credential isolation

The current Bridge preflight proceeds only when all discovered PHP-FPM pools resolve to the same non-root UID/GID pair. That logic is not sufficient for a multi-application host and must be replaced with per-application pool resolution.

The broker now requires each credential destination to be exactly `/var/lib/nadi-bridge/{application_id}/credential`, outside the Laravel application tree. It stores the credential as runtime_uid:runtime_gid with mode 0600. The root-owned parent directory is not writable by application users. If multiple Laravel applications share the same PHP-FPM UID, a process compromised in one application may be able to read another application's credential file whenever the filesystem path is traversable. Mode 0600 does not isolate processes that share the file owner UID.

The provisioning implementation must not claim per-application OS-level credential isolation when UIDs are shared. The secure default is to require a distinct non-root runtime UID for each application whose credential must be isolated. If the deployment intentionally uses one shared PHP-FPM UID, that is a shared trust boundary and must not be presented as per-application isolation.

## Required helper lifecycle

1. Validate the bounded JSON request, reject duplicate keys/unknown fields/trailing data, and validate every application mapping.
2. Verify the signed release manifest using the embedded trusted Ed25519 key, select the supported Linux artifact, and verify its SHA-256 before installation.
3. Validate the staged artifact and all application paths without following symlinks.
4. Create or validate the fixed `nadi-agent` service account and fixed NADI directories. Never accept arbitrary account names or paths from the request.
5. Install the verified Agent binary atomically and install only trusted, root-owned service/configuration assets.
6. Create the root-owned broker mapping for all applications and exact systemd write-path permissions.
7. Run the single Agent enrollment as `nadi-agent`, passing the one-time token through stdin, not argv or environment variables.
8. Consume only the non-secret enrollment summary and match all Central application IDs to the prevalidated local application records by application key.
9. Start only the fixed control-plane broker/Agent services after post-install verification. Monitoring remains blocked by Central approval, a valid signed Activation Grant, and accepted Grant acknowledgement.
10. If Central enrollment succeeded but a later local step fails, preserve the Agent state and report the partial outcome. Do not delete local state or automatically attempt another enrollment: Central enrollment cannot be rolled back by local filesystem rollback.

## Credential and activation handoff

The Agent state contains Agent and per-application credentials. The helper and Bridge must never read, parse, display, return, or copy state.json.

The existing local handoff protocol uses a root-owned broker and kernel-authenticated Unix socket peer credentials. The broker mapping must be generated from the validated multi-application inventory. Credential publication does not open the Bridge activation gate; the signed Activation Grant and acknowledgement gate remains authoritative.

## Latest work in this checkpoint

- [x] Read-only Central contract review is recorded in [CENTRAL-CONTRACT-VERIFICATION.md](CENTRAL-CONTRACT-VERIFICATION.md). Central was not modified.
- [x] Agent enrollment tolerates missing optional server IPv4 data, matching Central's nullable `server.ip_address`.
- [x] Control Poll fixture uses Central's string-valued `endpoint` and asserts decoding.
- [x] Broker credential destinations are constrained to `/var/lib/nadi-bridge/{application_id}/credential`; writable Laravel application trees are rejected.
- [x] Broker mapping validation now requires UUID application IDs, fixed credential and activation-state destinations, distinct runtime UIDs, canonical non-root application paths, and non-overlapping application paths.
- [x] Broker tests cover rejection of application-tree destinations and duplicate runtime UIDs.
- [x] Broker systemd base unit is limited to `/run/nadi-agent`; the Agent unit's write scope is limited to `/var/lib/nadi-agent`.
- [ ] The helper still needs to generate a root-owned systemd drop-in containing only the exact per-application credential parent directories.
- [ ] Bridge runtime configuration still defaults to `storage/app/private/nadi/credential`; it must resolve the external per-application path before end-to-end credential handoff can work.
- [ ] The helper has not yet been implemented. No root provisioning, enrollment invocation, service start, or deployment was performed.

Latest Agent source commit for this checkpoint: `a0a1fdd434c93702ea858d88f30eff8fe5ecd302`. The previous complete Go validation recorded in PR #2 applies to commit `55ca52ba6de447344bb5f06f80e7d924ef89f863`; no workflow run has been confirmed for the newer broker-hardening commits. Do not treat this checkpoint as CI-validated.



- [x] Broker credential destinations are constrained to `/var/lib/nadi-bridge/{application_id}/credential`; writable Laravel application trees are rejected.
- [x] Broker unit source has the fixed runtime directory boundary; the installer must add exact per-application credential-directory write paths rather than granting the whole Bridge data root.
- [x] Broker tests cover rejection of application-tree destinations and acceptance of the fixed external destination.
- [ ] Bridge runtime configuration still defaults to `storage/app/private/nadi/credential`; it must be updated to resolve the same external per-application path before end-to-end credential handoff can work.

## Broker artifact reconciliation added in the latest increment

- [x] Added a strict reconciler that accepts only the non-secret enrollment summary emitted by the Agent CLI and matches every Central application key to exactly one prevalidated local mapping.
- [x] Reconciler derives the only allowed credential and activation-state destinations from Central-issued application UUIDs; callers cannot choose arbitrary output paths.
- [x] Reconciler validates the complete broker mapping through the broker's own configuration validator before emitting any artifact.
- [x] Added deterministic broker mapping JSON and a systemd drop-in containing only each application's exact `/var/lib/nadi-bridge/{application_id}` write path.
- [x] Added unit tests for multi-application reconciliation, deterministic ordering, exact write-path scope, missing application mappings, unknown summary fields, and invalid mappings.
- [ ] The artifact builder is not yet a root-owned installer: it does not create directories, write files, install binaries/keys/units, invoke enrollment, enable services, or verify runtime status.
- [ ] The Go tests and CI workflow for this increment have not yet been confirmed.

The new code is in `internal/provision/broker_artifacts.go` and `internal/provision/broker_artifacts_test.go`. It is a bounded preparation step for the helper, not a claim that provisioning is complete.

## Atomic broker artifact installation increment

- [x] Added a root-only installation entry point for the validated broker mapping and generated per-application systemd drop-in.
- [x] The installer re-derives expected mapping JSON and drop-in content from the validated broker configuration; caller-supplied bytes must match exactly.
- [x] Creates/validates the fixed Bridge credential root and per-application directories without following symlinks; enforces root ownership and restrictive permissions.
- [x] Writes mapping and drop-in files using same-directory temporary files, fsync, atomic rename, and directory fsync.
- [x] Added tests for file modes, credential directory ownership/mode, exact drop-in scope, mismatched artifacts, and symlink rejection.
- [x] The installer deliberately does not reload systemd or start services. Those actions belong to the not-yet-implemented privileged orchestration layer, after all provisioning prerequisites and rollback boundaries are in place.
- [ ] This is still not the `nadi-provision --request-stdin` helper and does not install or verify the Agent binary, trusted activation key, service units, system user, or enrollment lifecycle.
- [ ] Go CI for this increment is pending.

Files: `internal/provision/broker_artifact_install.go` and `internal/provision/broker_artifact_install_test.go`.

## Canonical filesystem layout decision and migration

ADR-0001 records the accepted decision to use the five baseline directories from Master Architecture section 10.4: `/opt/nadi`, `/etc/nadi`, `/var/lib/nadi`, `/var/log/nadi`, and `/run/nadi`. The Bridge credential root `/var/lib/nadi-bridge/{application_id}` remains a separate per-application security boundary.

The Agent implementation, broker mapping, activation-state destination, socket, systemd units, embedded unit assets, and their tests have now been migrated from the former `/etc/nadi-agent`, `/var/lib/nadi-agent`, and `/run/nadi-agent` paths to the canonical layout. `/opt/nadi/bin/nadi-agent` was already canonical and remains unchanged.

The Laravel Bridge config no longer defaults credentials into Laravel storage. `NADI_CREDENTIAL_FILE` and `NADI_ACTIVATION_STATE_FILE` are installer-managed environment values and default to null, preserving fail-closed behavior until provisioning supplies the per-application paths. The packaged Agent unit and Bridge handoff documentation use the canonical locations.

This source migration is not a production migration. No existing host state was moved, no services were restarted, and no Central repository changes were made. Installer directory creation, ownership/mode validation, and a safe restore/migration policy remain required.

## Current implementation gaps

- [ ] Root-owned `nadi-provision` executable and strict request parser.
- [x] Multi-application Bridge inventory configuration and per-application PHP-FPM pool identity resolution are implemented in the Bridge PR branch.
- [x] Bridge-to-helper request contract now carries one enrollment manifest and an `applications` array; Bridge validation tests passed in workflow run #54.
- [ ] Root-owned installation lifecycle, one-time enrollment invocation, summary reconciliation, exact systemd drop-in generation, and post-install verification.
- [ ] Root-owned installation of Agent/broker binaries, trusted keys, systemd units, mapping, and exact write-path drop-ins.
- [ ] Single enrollment invocation and summary-to-mapping reconciliation.
- [ ] Safe partial-failure handling, post-install verification, and tests.
- [ ] End-to-end tests across Central, Agent, Bridge, and broker.

No Central changes are required for the confirmed one-Agent/many-applications enrollment model. No monitoring has been activated, and no production host has been modified.


## CI validation confirmation — 2026-11-24

The validation rerun for Agent commit `e69151c4b9e5a605f9e28417e48ea4bd7d150d0f` has completed successfully.

Workflow run #198: https://github.com/simfinance/nadi-agent/actions/runs/45301631835

Both jobs completed with success:
- [x] Go formatting job.
- [x] `gofmt` verification.
- [x] `go test ./...`.
- [x] `go test -race ./...`.
- [x] `go vet ./...`.
- [x] Linux AMD64 build.
- [x] Linux ARM64 build.

This supersedes the earlier "CI pending" statements above for the atomic broker artifact installer increment. The validation applies to the exact Agent commit listed above; documentation-only updates after that commit do not change the validated Go source. It does not establish root-helper completion, deployment readiness, or an end-to-end Central/Agent/Bridge test.

## Additional integration gap confirmed during Bridge review

The Bridge `PrivilegedProvisioner::installAgent()` currently treats every non-zero helper exit as a generic provisioning failure before decoding stdout. That response path cannot yet distinguish a failure before Central enrollment from a failure after Central has consumed the one-time token. The future helper/Bridge contract must return and validate a bounded, non-secret partial-outcome envelope even when the helper exits non-zero, without exposing credentials or state.json. Do not retry enrollment automatically after an uncertain or confirmed Central registration.

The Bridge config still defaults `credential_file` to Laravel's `storage/app/private/nadi/credential`, while the broker accepts only `/var/lib/nadi-bridge/{application_id}/credential`. This remains an explicit Bridge runtime integration gap and must be fixed together with tests for application-ID validation and path derivation; changing only the config default would be insufficient.

The architecture path alignment blocker remains unresolved. Root provisioning orchestration must not be completed against either path family until the project owner resolves the Master Architecture section 10.4 versus Agent-specific path decision.
