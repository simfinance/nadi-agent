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

The Bridge config has now removed the unsafe Laravel-storage credential default. `credential_file` and `activation_state_file` are read from installer-managed `NADI_CREDENTIAL_FILE` and `NADI_ACTIVATION_STATE_FILE` environment values and default to null. This is intentionally fail-closed; the privileged helper still must derive and provision the exact per-application paths from Central-issued application UUIDs, and Bridge-side validation/tests for that identity-to-path binding remain pending.

The canonical path decision is resolved by ADR-0001 and the source migration is committed. Remaining installer work must create and validate the five canonical directories, install configuration/key/service assets at those locations, and preserve the Master Architecture restore/idempotency requirements. This is not a production migration.


## Canonical path migration validation — latest checkpoint

- [x] ADR-0001 accepted and committed.
- [x] Agent defaults now use `/var/lib/nadi`, `/etc/nadi/keys`, and `/run/nadi`.
- [x] Broker mapping and activation-state paths now use `/etc/nadi/bridge-mappings.json` and `/run/nadi/bridge-state/{application_id}.json`.
- [x] Broker and Agent systemd source units and embedded assets now use the canonical `/etc/nadi`, `/var/lib/nadi`, and `/run/nadi` roots.
- [x] Broker/config/provisioning tests updated to assert the canonical locations.
- [x] Bridge no longer defaults credential storage to the Laravel application storage tree; the installer-managed environment settings default to null.
- [x] Bridge packaged Agent unit and handoff documentation aligned with canonical paths.
- [ ] Latest Agent CI validation is pending after a test-fixture correction. Workflow #45309436924 exposed one stale test expectation still pointing to `/etc/nadi-agent/bridge-mappings.json`; the production code and test fixture have now both been aligned to `/etc/nadi/bridge-mappings.json`. The correction is committed as `922e06ff0f4ccb4c189b424cae4d3a48402264d6`; a successful validation run for this corrected commit has not yet been confirmed.
- [x] Latest Bridge CI validation passed. Workflow #45309364276: https://github.com/simfinance/nadi-laravel-agent/actions/runs/45309364276.

Latest Agent source/test commit: `922e06ff0f4ccb4c189b424cae4d3a48402264d6`.
Latest Agent branch head at this checkpoint (documentation included): `b423bae95715de1e64604fac87570d6acc65e82b`.
Latest Bridge branch head: `5fd0a0159d3ee66a6dfa9a8138d266bc62f60332`.

The failed run is a real test failure, not a code-formatting issue. Do not mark the Agent path migration CI-passed until a run against the corrected branch head completes successfully.

The root-owned provisioning helper, fixed per-application path derivation/validation inside Bridge, systemd reload/start orchestration, post-install verification, rollback, and end-to-end tests remain incomplete. No Central files or production hosts were changed.


## Provisioning helper source foundation — 2026-11-24

The following implementation foundation has been added on the Agent branch:

- [x] Added the fixed `cmd/nadi-provision --request-stdin` executable entrypoint. It accepts no caller-selected command or path argument.
- [x] Added bounded helper outcome JSON with phase, enrollment status, retry-safety flag, version, application count, and a non-secret message.
- [x] Added signed release-manifest verification, Linux artifact selection, staged artifact ownership/path checks, and a second SHA-256 check before installation.
- [x] Added fixed `nadi-agent` account/group provisioning and canonical directory preparation.
- [x] Added atomic, root-owned installation of the Agent binary, activation public key, and fixed systemd unit assets. Existing non-identical files are not overwritten.
- [x] Added independent validation that each application path is canonical, has a regular `artisan` entrypoint, and uses a non-root UID/GID represented by a root-owned PHP-FPM pool configuration.
- [x] Corrected the broker activation-state directory parent to `/run/nadi`.
- [x] Corrected broker artifact installation so it preserves `/etc/nadi` mode `0750` and does not silently change the parent directory to `0755`.
- [x] Added helper output, PHP-FPM identity, and directory-permission tests.

### Release-blocking items discovered during implementation

The helper is a source prototype only. It is not installed on a host, signed as a separate trusted OS helper, or connected to a production sudoers rule.

The current helper orchestration must not be treated as release-ready because the Bridge `PRIVILEGED-PROVISIONING-BOUNDARY.md` contains a protocol inconsistency that needs an explicit decision:

- The protocol v1 `install_agent` request envelope includes the one-time enrollment token.
- The same document says the `install_agent` operation must not enroll the Agent.
- The document also requires a separate fixed operation for enabling and starting `nadi-agent.service`.

The recommended resolution is to split the fixed helper operations into `install_agent` (install only), `enroll_agent` (execute the signed-inventory enrollment as `nadi-agent`, token via stdin), and `start_agent` (enable/start only the fixed NADI services after enrollment and broker mapping verification). This is a proposed contract clarification, not an approved architecture change. Do not wire or release the current combined orchestration until the contract is approved and the Bridge adapter is updated consistently.
The operation split proposal is documented in [ADR-0002](ADR-0002-provisioning-helper-operation-lifecycle.md), status Proposed — awaiting explicit approval. It is not an implementation authorization.


Additional gaps remain:

- [ ] Implement a tested rollback journal for pre-enrollment filesystem/service-account changes.
- [ ] Implement the approved operation split and partial-outcome handling across the Bridge adapter.
- [ ] Implement identity restore/repair for an existing valid `/var/lib/nadi/state.json`. The current prototype deliberately refuses a new enrollment when that file exists; it does not yet satisfy the Master Architecture RESTORE requirement.
- [ ] Resolve how installer-managed Bridge identity values (`application_id`, `application_key`, credential path, activation-state path) are provisioned without silently editing client application configuration.
- [ ] Preserve the Bridge fail-closed defaults until the Central source-IP allowlist is verified by infrastructure and Bridge activation identity is correctly provisioned.
- [ ] Complete privileged helper tests, root/non-root integration tests, systemd lifecycle tests, rollback tests, and end-to-end tests.
- [ ] Publish and verify the separate helper through a trusted OS provisioning channel. Composer must not create, replace, or bootstrap it through sudo.

Latest full Agent CI including the helper source foundation: workflow #236 on commit `c8c439d7630ac55bf2f94f7d916e4d1e89d77c3f` passed gofmt, `go test ./...`, `go test -race ./...`, `go vet ./...`, Linux AMD64 build, and Linux ARM64 build. Run: https://github.com/simfinance/nadi-agent/actions/runs/45316553340.

The new helper source increment is under validation. Do not infer CI success from the previous run or from a formatting-only job. No Central files or production hosts were changed.

## Security hardening and installation UX checkpoint — 2026-11-24

- [x] PHP-FPM pool configuration validation now rejects symlinked directory components, non-root-owned or group/other-writable directories, symlink/non-regular pool files, unsafe ownership/modes, and file replacement between metadata inspection and open.
- [x] Added tests for symlinked PHP-FPM directory components, paths outside the configured root, and symlinked pool files.
- [x] Agent CI workflow #239 passed on branch head `51e5e41f837130a441f0240b1e6389671f4a94a9`: formatting, `go test ./...`, `go test -race ./...`, `go vet ./...`, Linux AMD64 build, and Linux ARM64 build. https://github.com/simfinance/nadi-agent/actions/runs/45321575260
- [x] Pull request #2 remains open and draft; current head is `51e5e41f837130a441f0240b1e6389671f4a94a9`. This CI result validates the current Go source checks only; it is not a privileged-host, systemd, rollback, or end-to-end test.

### Mandatory two-command customer installation experience

The customer-facing Laravel installation remains exactly:

```bash
composer require nadi/laravel-agent
php artisan nadi:install
```

No third customer command may be introduced for provisioning, enrollment, service activation, or verification. All required internal provisioning phases must be orchestrated by the single Artisan installer command, with narrow privilege escalation through the fixed trusted helper interface. Composer must not invoke sudo, install/replace the privileged helper, or run privileged Composer scripts.

The two-command requirement does not relax any security boundary: the Agent runtime remains non-root as `nadi-agent`; helper operations remain fixed and allowlisted; enrollment remains one request for the complete 1–20 application inventory; the one-use token must not appear in argv, environment, logs, or output; and monitoring remains blocked until per-application approval, a valid signed Activation Grant, and accepted acknowledgement.

### Approval gate remains open

ADR-0002 is still **Proposed — awaiting explicit approval**. Its proposed internal separation (`install_agent`, `enroll_agent`, `start_agent`) must not be treated as an accepted protocol or wired into the release installer until explicitly approved and implemented consistently in Agent and Bridge. The user-facing two-command requirement is a UX constraint, not approval of ADR-0002.

Outstanding release blockers remain: rollback journal, safe existing-Agent identity restore/repair, installer-managed Bridge identity provisioning, trusted OS helper packaging/bootstrap, root/non-root and systemd integration tests, and end-to-end validation. Central remains read-only; no production host has been modified.

## Accepted three-operation helper lifecycle — 2026-11-24

ADR-0002 was explicitly approved by the project owner on 2026-11-24. The approved contract is three fixed operations behind the same trusted helper invocation. This approval does not authorize production installation or waive release gates.

Implemented source changes on the Agent branch:

- [x] Replaced the exposed combined helper entrypoint with strict operation dispatch for `install_agent`, `enroll_agent`, and `start_agent`.
- [x] Added operation-specific request validation. `install_agent` rejects enrollment fields; `enroll_agent` rejects release/application fields; `start_agent` accepts no caller-selected fields.
- [x] `install_agent` verifies the signed release and artifact, validates the complete 1–20 application inventory and PHP-FPM identities, installs fixed assets, persists root-owned non-secret inventory metadata, and runs `systemctl daemon-reload`. It does not enroll or start services.
- [x] `enroll_agent` accepts only the complete enrollment manifest and one-time token, validates the manifest against the installed inventory, runs the fixed Agent as `nadi-agent`, consumes only the non-secret summary, and installs broker mappings and exact write-path drop-ins.
- [x] A root-owned non-secret enrollment-attempt marker is persisted before the Agent enrollment process starts. If a later invocation finds an attempt without a verified completion record, it fails closed as unknown/non-retryable; it does not submit another enrollment.
- [x] `start_agent` accepts no arguments beyond the operation envelope, verifies the enrollment/broker completion record and Agent state file metadata without reading `state.json`, then starts only the fixed NADI broker and Agent units.
- [x] Added Go request-decoder tests for operation-specific fields, unknown operations, and duplicate JSON keys.

Bridge changes:

- [x] The Bridge adapter now calls the same fixed helper invocation three times in order: `install_agent`, `enroll_agent`, then `start_agent`.
- [x] The enrollment token is excluded from the install request and is sent only in the enroll request standard input. It is not added to argv or environment.
- [x] Bridge response validation now recognizes the distinct `installed`, `enrolled`, and `completed` success phases and enforces their enrollment/retry invariants.
- [x] Added PHPUnit coverage for install-only and enrollment-complete outcomes.
- [x] Updated the Bridge privileged provisioning boundary to the accepted operation-specific protocol.

The customer-facing installation invariant remains exactly two commands:

```bash
composer require nadi/laravel-agent
php artisan nadi:install
```

All three helper operations are internal to the single Artisan installer execution. The infrastructure must still provide the trusted root-owned helper and exact narrow sudoers authorization; Composer does not install or replace the privileged helper.

### Current validation status

- Bridge workflow #62 (run ID 45323229422) passed PHP 8.2 and PHP 8.3 lint, PHPUnit, trust-anchor checks, bundled Agent binary verification, and Composer distribution checks: https://github.com/simfinance/nadi-laravel-agent/actions/runs/45323229422.
- Agent workflow #251 (run ID 45323236586) is marked `action_required` by GitHub and exposed no jobs, so it has not validated the new Go operations. The previous workflow #239 passed only the earlier PHP-FPM hardening source, not this lifecycle implementation: https://github.com/simfinance/nadi-agent/actions/runs/45323236586.
- Go formatting, unit/race tests, vet, and AMD64/ARM64 builds for the accepted lifecycle implementation remain unverified.

### Remaining blockers

- [ ] Obtain a runnable Agent CI validation for the new helper operation code and resolve any compile/test failures.
- [ ] Add integration tests for root-owned inventory/attempt/completion metadata, enrollment interruption, and service activation sequencing.
- [ ] Implement and test the pre-enrollment rollback journal.
- [ ] Implement Master Architecture RESTORE behavior for an existing valid Agent identity; the current helper still fails closed when `state.json` exists and does not yet restore identity.
- [ ] Complete trusted OS helper packaging/bootstrap and exact sudoers policy validation.
- [ ] Complete root/non-root, systemd lifecycle, rollback, and end-to-end Central/Agent/Broker/Bridge tests.

No Central source or production host was modified. The PR remains draft and the helper remains a source implementation, not a production-ready installer component.

## Master specification alignment review — 2026-11-24

The uploaded Master Architecture Technical Specification v1.0 and Agent Side Monitoring Specification v1.0 were reopened and checked against the current helper implementation.

Confirmed constraints preserved by this increment:

- Developer-facing install flow remains exactly `composer require nadi/laravel-agent` followed by `php artisan nadi:install`.
- Composer is not run as root and does not install or replace the privileged helper.
- No manual Go, Python, Node.js, Agent binary, systemd unit, or Linux command installation is delegated to the application developer.
- The Agent runtime remains the dedicated non-root `nadi-agent` user.
- Privileged actions use only the fixed root-owned helper invocation and three operation allowlist.
- Nginx, firewall, PHP-FPM, Supervisor, and client application configuration are not silently modified.
- Agent monitoring remains subject to the per-application Central approval and signed, acknowledged Activation Grant gate.

### Explicit unresolved specification gaps — do not silently treat as compliant

- **RESTORE behavior:** Master Architecture requires reinstall to restore an existing valid Agent identity and requires `recovery_required` when it cannot be verified. The current helper still fails closed when `/var/lib/nadi/state.json` exists; it does not yet implement Agent-mediated identity restore/repair.
- **Canonical state subdirectory:** ADR-0001 describes persistent state under `/var/lib/nadi/state/`, while the current Agent StateStore still uses `/var/lib/nadi/state.json`. This path discrepancy requires a deliberate migration/compatibility decision and tests; do not silently move existing state.
- **Additional application lifecycle:** Master Architecture describes an additional Laravel application reusing the existing Agent and authorizing a new application. The inspected Central implementation currently has no append-application endpoint and rejects a second enrollment for an already registered `agent_instance_id`. Current supported enrollment is therefore one initial request containing all 1–20 applications on that server. Supporting later additions requires a Central API/architecture decision; Central remains read-only in this work.
- **Rollback:** Master and Agent Side specifications require safe rollback/idempotency. The current helper operations are designed to be retry-safe before enrollment and non-retryable after an uncertain enrollment attempt, but a complete transaction rollback journal and recovery test suite are still missing.
- **Privileged helper distribution:** The trusted root-owned helper and exact sudoers authorization remain an infrastructure prerequisite. Composer must not bootstrap or replace them with sudo.
- **Bridge runtime identity:** Installer-managed per-application Bridge identity and environment configuration must be completed without silently editing client application configuration.

These are release blockers, not reasons to weaken the two-command customer experience. No Central source or production host was modified.
