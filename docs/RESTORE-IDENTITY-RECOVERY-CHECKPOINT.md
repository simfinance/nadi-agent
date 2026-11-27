# RESTORE Agent Identity — Recovery State Matrix

Status: implementation checkpoint for Boundary 1. This document records the enforced local recovery behavior and its limits; it does not authorize re-enrollment, key replacement, state migration, or production deployment.

## Governing policy

The binding recovery sequence is:

1. Fail closed when the existing Agent identity or persisted state cannot be verified.
2. Reconcile the prior server, Agent, application registrations, and any uncertain enrollment outcome with NADI Central.
3. Obtain explicit, attributable operator authorization after reconciliation.
4. Re-enroll only after reconciliation and authorization are both complete.

RESTORE and re-enrollment are separate operations. RESTORE preserves the existing Agent identity and credentials. It must not silently create a replacement identity, issue or submit a new token, or retry an uncertain Central enrollment.

## Local Agent state decision matrix

| Persisted state | Integrity key | Installation marker | Required behavior |
|---|---|---|---|
| Missing | Missing | Missing | Treat as a fresh installation; generate a new integrity key and initial Agent identity |
| Valid and verifiable | Present | Present | Load the existing identity; preserve its identifiers and credentials |
| Missing | Present | Present | Fail closed; report recovery required; never generate a replacement identity |
| Present | Missing | Present or absent | Fail closed; state cannot be authenticated |
| Missing | Missing | Present | Fail closed; prior installation is evidenced by the marker |
| Present but malformed, unsupported, or signature-invalid | Present | Present | Fail closed; do not overwrite or repair the persisted identity |
| Valid state, but machine fingerprint differs | Present | Present | Fail closed; do not bind the identity to a different machine |

The implementation uses the integrity key and persistent `agent.lock` marker to distinguish a fresh initialization from a known existing installation. `identity.Ensure()` creates an initial UUID only when the store reports a fresh installation. Missing state on an existing installation returns a recovery-required error.

## Root-owned provisioning evidence

The local Agent cannot prove that an installation existed if its entire state directory, including `agent.lock` and the integrity key, has been deleted. The trusted provisioning helper therefore supplies an independent root-owned evidence boundary:

- A prior root-owned completion record binds the Agent instance ID, Central Agent ID, and Central Server ID.
- If that completion record exists but the Agent state cannot be verified by the fixed Agent-side verifier, the helper must return `recovery_required` or an unknown outcome.
- The helper must not parse `state.json`; it invokes the fixed verifier as `nadi-agent` and consumes only the bounded non-secret identity summary.
- A missing or unverifiable completion binding must not be interpreted as permission to enroll again.

This is defense in depth, not proof against a compromised root account or a compromised `nadi-agent` process.

## Crash and deletion limitations

- The persistent `agent.lock` marker is created before the integrity key. A process crash after marker creation but before key creation can conservatively leave the installation in a fail-closed recovery state. This favors preventing identity replacement over automatic recovery.
- If the entire state directory is deleted, local Agent evidence is gone. The root-owned provisioning completion record is expected to detect the prior installation and block fresh initialization through the helper workflow.
- If both the state directory and the independent root-owned provisioning evidence are deleted or compromised, local software cannot reliably infer the former identity. Central reconciliation and operator-controlled recovery remain mandatory.
- Ed25519 state integrity detects state-file-only modification when the integrity key remains protected. It does not protect against root or Agent-process compromise because the Agent process can access its local signing key.

## Non-goals and decisions still open

This checkpoint does not define or authorize:

- Automatic state reconstruction or identity replacement.
- Integrity-key rotation, backup, escrow, or recovery.
- Migration from unsigned legacy state.
- Migration from `/var/lib/nadi/state.json` to the ADR-0001 directory form `/var/lib/nadi/state/`.
- Changes to NADI Central enrollment or reconciliation APIs.
- Automatic retry after an uncertain Central enrollment result.
- Production installation or activation.

These require separate reviewed decisions. In particular, a key that is missing cannot be recreated while preserving the authenticity of the old signed state.

## Validation evidence

Agent workflow #384, run ID `45538688220`, completed successfully on commit `9d3a675db7fae32616af5d018df1689691cc2dca`:

- Go formatting check
- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- Linux AMD64 build
- Linux ARM64 build

Run: https://github.com/simfinance/nadi-agent/actions/runs/45538688220

This validates the Go source checks for that commit. It does not constitute a privileged-host, live systemd, production recovery, or end-to-end Central/Agent/Broker/Bridge test.

## Boundary 1 exit criteria

Boundary 1 remains open until all of the following are evidenced:

- RESTORE preserves the same Agent instance ID, Central Agent ID, Central Server ID, credentials, and enrolled application identities.
- Every missing, corrupt, mismatched, or unverifiable existing identity enters a fail-closed recovery state.
- The helper never reads or parses `state.json`; only the Agent-side verifier may inspect it.
- Root-owned provisioning evidence prevents a deleted Agent state directory from being treated as a fresh install.
- Recovery follows fail closed → Central reconciliation → explicit operator authorization → re-enrollment only when authorized.
- The recovery behavior is validated across interrupted operations and the relevant privileged/non-root execution boundary.

No Central source or production host was changed for this checkpoint. PR #2 remains Draft.
