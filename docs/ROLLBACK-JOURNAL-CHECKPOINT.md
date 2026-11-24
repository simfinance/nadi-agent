# Provisioning Rollback Journal — Implementation Checkpoint

Status: journal core, fresh-install (`install_agent`) integration, and exclusive helper-operation locking are implemented in the current branch. Agent-mediated identity RESTORE is also implemented as a fail-closed source path, but its metadata writes are not yet journaled. Bridge artifact reconciliation after enrollment, failure-injection coverage, crash/reboot recovery, and full E2E validation remain pending. This is not a production-ready rollback implementation.

## Safety contract

The journal is root-owned metadata. It must never contain Agent credentials, application credentials, enrollment tokens, raw Agent state, or copies of `state.json`.

Each resource mutation follows this order:

1. Persist an `intent` action before the mutation.
2. Perform one fixed, allowlisted mutation.
3. Read back the resulting resource metadata and persist an `applied` fingerprint.
4. On failure, process applied actions in reverse order.
5. Remove a resource only if its current device/inode, owner, group, mode, size, and (for files) SHA-256 still match the recorded fingerprint.
6. Persist the rollback result after each resource.

An intent without a post-operation fingerprint is ambiguous. The helper must preserve that resource and stop with `recovery_required`; it must not infer that the resource belongs to the interrupted transaction.

## Journal format and storage

- Schema version: 1.
- Operation: fixed `install_agent`.
- Phases: `in_progress`, `rollback_required`, `rolled_back`, `committed`.
- Resource kinds: regular file and directory only.
- Resource states: `intent`, `applied`, `rolled_back`.
- File fingerprints include device, inode, UID, GID, mode, size, and SHA-256.
- Directory fingerprints include device, inode, UID, GID, and mode.
- Journal updates use a same-directory temporary file, file fsync, atomic rename, and parent-directory fsync.
- Journal file permissions are 0600 and ownership is the helper's effective UID/GID (root in production).

## Deliberate exclusions

- Account/group creation and systemd state are not automatically reversed by this first journal increment.
- A file or directory with an incomplete fingerprint is never deleted automatically.
- Non-empty directories are not recursively removed.
- Existing resources are never recorded as transaction-created resources.
- Enrollment and any Central-side effects are outside local rollback. Once enrollment may have been submitted, preserve Agent state and require identity reconciliation instead of rollback or re-enrollment.

## Initial integration requirements — current status

The fresh-install `install_agent` path now creates the journal before its first journaled account/filesystem action, records transaction-created directory and file mutations, commits after inventory installation and systemd daemon reload, and invokes reverse-order rollback on pre-enrollment failure.

The following integration is still required:

- Extend transaction tracking to the identity RESTORE metadata path. RESTORE must never roll back, rewrite, or delete the existing Agent state or credentials.
- Define safe recovery for broker mapping, per-application credential-directory, and systemd drop-in writes after Central enrollment. These are post-enrollment local mutations; failure must preserve Agent state and must never imply Central enrollment was undone.
- Add failure injection at every mutation boundary and crash/reboot recovery tests.
- Ensure the Bridge adapter handles `rolled_back` and `recovery_required` as explicit bounded outcomes without prompting for another enrollment token.

A stale or malformed journal must block another install attempt until explicitly reconciled.

## Current implementation increment

- [x] Added a durable journal at the fixed temporary path `/etc/.nadi-provisioning-journal.json`; it is root-owned in the privileged runtime and mode 0600.
- [x] The journal is created before the first fresh-install account or filesystem mutation.
- [x] `install_agent` records directory and file creation intent before mutation, then records a device/inode/owner/group/mode fingerprint and SHA-256 for files after successful creation.
- [x] Fresh-install failure invokes reverse-order rollback. Files are removed only when their current fingerprint still matches; directories are removed only when their fingerprint matches and they are empty.
- [x] A resource with an intent but no verified post-operation fingerprint is preserved and reported as `recovery_required`.
- [x] The fixed `nadi-agent` service identity (system group and account) is explicitly retained; the helper does not attempt to delete an identity that may predate the transaction or be in use.
- [x] Existing directories with mismatched ownership or mode are rejected instead of silently chmodded by the journal-aware fresh-install path.
- [x] A stale in-progress journal is rolled back before a new fresh install. A committed journal is accepted only when the root-owned inventory matches the signed release and requested application inventory.
- [x] All three privileged helper operations are serialized with an exclusive, root-owned mode-0600 lock at `/etc/.nadi-provisioning.lock`; concurrent invocations fail closed.
- [x] Added unit tests for file/directory rollback, modified-resource refusal, un-fingerprinted intent refusal, retained service account, journal parent permissions, and journal-aware installation helpers.

## Remaining integration and verification

- [ ] Add crash/reboot recovery tests for stale lock files and lock acquisition across separate processes.
- [ ] Extend transaction tracking to the RESTORE metadata path without ever touching the existing Agent state or credentials.
- [ ] Define the recovery behavior for broker mapping/drop-in writes after Central enrollment. Those writes occur after the irreversible enrollment boundary; Agent state must be preserved and local rollback must not imply Central enrollment was undone.
- [ ] Add fault-injection tests at every mutation boundary, including process interruption between intent, filesystem mutation, fingerprint persistence, rollback deletion, and journal update.
- [ ] Verify behavior on supported Linux filesystems and systemd hosts, including directory fsync and ownership behavior.
- [x] Go validation workflow #329 (`45332623960`) passed on code commit `7126fe4de8eb479645f02a617baef92ff4b0f143`: gofmt, `go test ./...`, `go test -race ./...`, `go vet ./...`, Linux AMD64, and Linux ARM64.
- [ ] Add root/non-root/systemd end-to-end coverage on a disposable Linux host.
- [ ] Confirm the Bridge adapter handles `rolled_back`, `recovery_required`, and retained committed-journal responses without prompting for a new token.

The current implementation is an integrated first increment for the reversible fresh-install filesystem phase only. It does not make account creation reversible, does not roll back Central enrollment, and does not yet make RESTORE or the complete three-operation lifecycle transactionally recoverable.
