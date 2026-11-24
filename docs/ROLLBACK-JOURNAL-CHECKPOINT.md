# Provisioning Rollback Journal — Implementation Checkpoint

Status: journal core, fresh-install (`install_agent`) integration, identity RESTORE (`restore_agent`) transaction tracking, and exclusive helper-operation locking are implemented in the current branch. RESTORE journals only transaction-created canonical directories, signed Agent assets, Bridge mapping/drop-in artifacts, and root-owned provisioning inventory/completion metadata; it never journals or modifies the existing Agent state or credentials. Enrollment-time Bridge artifact reconciliation after Central registration, failure-injection coverage, crash/reboot recovery, and full E2E validation remain pending. This is not a production-ready rollback implementation.

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
- Operation: fixed internal transaction kinds `install_agent` and `restore_agent`; these do not add public helper operations.
- Phases: `in_progress`, `rollback_required`, `rolled_back`, `committed`.
- Resource kinds: regular file and directory only.
- Resource states: `intent`, `applied`, `rolled_back`.
- File fingerprints include device, inode, UID, GID, mode, size, and SHA-256.
- Directory fingerprints include device, inode, UID, GID, and mode.
- Journal updates use a same-directory temporary file, file fsync, atomic rename, and parent-directory fsync.
- Journal file permissions are 0600 and ownership is the helper's effective UID/GID (root in production).

## Deliberate exclusions

- Account/group creation is retained and is not automatically reversed. RESTORE journals only transaction-created systemd drop-in files and directories; `systemctl daemon-reload` itself is not reversible and service activation is not performed by this transaction.
- A file or directory with an incomplete fingerprint is never deleted automatically.
- Non-empty directories are not recursively removed.
- Existing resources are never recorded as transaction-created resources. An existing immutable file is accepted only when its owner, group, mode, size, and bytes exactly match the expected artifact; mismatches are rejected without replacement.
- Enrollment and any Central-side effects are outside local rollback. Once enrollment may have been submitted, preserve Agent state and require identity reconciliation instead of rollback or re-enrollment.

## Initial integration requirements — current status

The fresh-install `install_agent` path now creates the journal before its first journaled account/filesystem action, records transaction-created directory and file mutations, commits after inventory installation and systemd daemon reload, and invokes reverse-order rollback on pre-enrollment failure.

The following integration is still required:

- Extend the same journal discipline to broker mapping, per-application credential-directory, and systemd drop-in writes performed by the fresh `enroll_agent` operation after Central registration. A failure must preserve Agent state and must never imply Central enrollment was undone.
- Add failure injection at every mutation boundary and crash/reboot recovery tests. Restart-oriented journal tests reload persisted RESTORE journals: a fingerprinted file is removed safely, an intent without a persisted fingerprint remains untouched and leaves the journal in `rollback_required`, and recovery is idempotent when resource removal completed before the process stopped.
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
- [x] Extend transaction tracking to identity RESTORE metadata, canonical directories, missing signed assets, broker mapping/drop-in artifacts, and completion metadata. The existing Agent state and credentials are excluded from the journal and are never modified by rollback.
- [ ] Extend transaction tracking to broker mapping/drop-in writes performed by `enroll_agent` after Central registration. Preserve Agent state and report a non-retryable partial outcome if local reconciliation fails.
- [ ] Add fault-injection tests at every mutation boundary, including process interruption between intent, filesystem mutation, fingerprint persistence, rollback deletion, and journal update.
- [x] Add focused persisted-journal reload tests for an applied RESTORE file and an ambiguous intent; the former rolls back by fingerprint and the latter is preserved fail-closed.
- [x] Add an idempotent recovery test for interruption after resource deletion but before the journal records `rolled_back`.
- [ ] Verify behavior on supported Linux filesystems and systemd hosts, including directory fsync and ownership behavior.
- [x] Go validation workflow #345 (`45335634194`) passed on commit `77c7a7dc26d09e87e5694686433754b79d351536`: gofmt, `go test ./...`, `go test -race ./...`, `go vet ./...`, Linux AMD64, and Linux ARM64.
- [ ] Re-run Go validation for the additional idempotent RESTORE recovery test at commit `db314136b2a50d32cf83a0b3b98e8abb9c5eb248`.
- [ ] Add root/non-root/systemd end-to-end coverage on a disposable Linux host.
- [ ] Confirm the Bridge adapter handles `rolled_back`, `recovery_required`, and retained committed-journal responses without prompting for a new token.

The current implementation provides journal coverage for the fresh-install filesystem phase and the local filesystem mutations performed by identity RESTORE. RESTORE preserves the existing Agent state and credentials, and rollback is limited to fingerprint-matching resources created by that RESTORE transaction. It does not make account creation reversible, does not reverse the systemd daemon-reload operation, does not roll back Central enrollment, and does not make the complete three-operation lifecycle transactionally recoverable. The RESTORE implementation and persisted-journal reload tests passed Go validation workflow #345. An additional idempotent recovery test was committed afterward and still requires CI validation at the latest branch head.
