# Provisioning Rollback Journal — Implementation Checkpoint

Status: journal core implemented; integration with the three provisioning operations remains pending. This is not a production-ready rollback implementation.

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

## Integration still required

The helper must create the journal before the first reversible filesystem mutation, then instrument directory and file creation in `install_agent`, broker artifact installation, and relevant restore paths. It must commit only after the installed inventory and all required local assets pass verification. Failure handling must run rollback and return a non-secret bounded status. A stale or malformed journal must block another install attempt until explicitly reconciled.

The current implementation only provides the journal data model, durable atomic persistence, resource fingerprints, and fail-closed reverse rollback primitives. It does not yet connect those primitives to installer mutations or invoke rollback automatically.
