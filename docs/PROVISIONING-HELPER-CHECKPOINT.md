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
- Broker mapping schema and systemd source unit.
- An independent release-manifest verifier foundation.
- An opt-in CLI output containing only non-secret enrollment identity metadata. The output excludes Agent and application credentials and is intended for the provisioning helper; it does not expose or copy state.json.

The Go enrollment manifest already supports 1–20 applications in a single request. The missing work is primarily the multi-application Bridge inventory, the root-owned helper, and their integration.

## Existing Bridge request and mismatch

The current Bridge `PrivilegedProvisioner` still sends a singular `application` object with one Laravel base path, one enrollment manifest, and one PHP-FPM UID/GID pair.

That request shape cannot represent the confirmed Central model for a server hosting multiple Laravel applications. It must be replaced before the helper protocol is frozen.

The target protocol must carry:

- One signed Agent release manifest, detached signature, and staged artifact path.
- One enrollment manifest containing all 1–20 application entries.
- An `applications` array containing one local mapping record per application: stable application key, canonical Laravel base path, runtime UID, and runtime GID.
- One one-time enrollment token for the entire Agent.
- No caller-selected commands, executable paths, service names, file modes, credential destinations, or arbitrary system paths.

The helper must verify that every mapping record corresponds to exactly one application key in the enrollment manifest. Duplicate keys, duplicate or overlapping application paths, unresolved runtime identities, and more than 20 applications must fail closed.

## PHP-FPM identity and credential isolation

The current Bridge preflight proceeds only when all discovered PHP-FPM pools resolve to the same non-root UID/GID pair. That logic is not sufficient for a multi-application host and must be replaced with per-application pool resolution.

The broker stores each application credential as runtime_uid:runtime_gid with mode 0600. If multiple Laravel applications share the same PHP-FPM UID, a process compromised in one application may be able to read another application's credential file whenever the filesystem path is traversable. Mode 0600 does not isolate processes that share the file owner UID.

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

## Current implementation gaps

- [ ] Root-owned `nadi-provision` executable and strict request parser.
- [ ] Multi-application Bridge inventory and PHP-FPM pool resolution.
- [ ] Multi-application Bridge-to-helper request contract and tests.
- [ ] Root-owned installation of Agent/broker binaries, trusted keys, systemd units, mapping, and exact write-path drop-ins.
- [ ] Single enrollment invocation and summary-to-mapping reconciliation.
- [ ] Safe partial-failure handling, post-install verification, and tests.
- [ ] End-to-end tests across Central, Agent, Bridge, and broker.

No Central changes are required for the confirmed one-Agent/many-applications enrollment model. No monitoring has been activated, and no production host has been modified.
