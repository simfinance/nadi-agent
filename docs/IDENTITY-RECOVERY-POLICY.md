# NADI Agent Identity Recovery Policy

**Status:** Accepted by project owner  
**Accepted:** 2026-11-25  
**Scope:** NADI Agent identity, persisted state, integrity key, RESTORE, and re-enrollment recovery

## Normative rule

NADI Agent identity recovery MUST use the following sequence:

**Fail closed → reconcile with NADI Central → obtain explicit authorization → re-enroll only when authorized.**

This is a binding NADI project rule. It supplements the existing architecture and implementation specifications. It does not silently amend or replace ADR-001 through ADR-009.

## 1. Fail closed

When an existing Agent installation is detected and its identity or persisted state cannot be verified, the Agent and provisioning helper MUST stop the affected restore, enrollment, or service-activation operation in a non-retryable recovery-required state.

Examples include:

- `state.json` is missing, malformed, unsigned, or fails integrity verification.
- The state-integrity private key is missing, malformed, unsafe, or does not verify the persisted state.
- The machine fingerprint differs from the persisted identity.
- The Agent instance ID, Central Agent ID, Central Server ID, or application identity mapping is incomplete or inconsistent.
- Root-owned provisioning completion metadata conflicts with the Agent-side identity summary.
- The prior enrollment outcome is uncertain, including an enrollment-attempt marker without a verified completion record.

In these cases the implementation MUST:

- Preserve existing Agent state, integrity keys, credentials, enrollment markers, and recovery evidence.
- NOT generate a replacement Agent identity or silently initialize a fresh state over an existing installation.
- NOT automatically issue, submit, or retry an enrollment token.
- NOT activate Agent services or monitoring on the basis of an unverified identity.
- Report a bounded, non-secret recovery-required status. Secrets and credential material MUST NOT be emitted in diagnostics.

A missing integrity key alongside an existing state file is a recovery condition, not permission to generate a new key.

## 2. Reconcile with NADI Central

Before any re-enrollment is considered, the existing identity and enrollment outcome MUST be reconciled with NADI Central.

Reconciliation MUST establish, to the extent Central records permit:

- Whether the prior server and Agent registration exists.
- The existing Central Agent ID and Server ID, where known.
- The status of every application registration associated with that Agent.
- Whether an earlier enrollment request was accepted, rejected, or remains uncertain.
- Whether existing credentials or registrations have been revoked, superseded, or remain active.

An uncertain Central outcome MUST remain non-retryable until it is resolved. Local absence or corruption of state is not evidence that Central has no registration.

The reconciliation procedure MUST NOT expose credentials or require the helper to parse `state.json`. The Agent remains the authority for reading and verifying its own state; the helper may consume only the bounded, non-secret identity summary.

## 3. Explicit authorization before re-enrollment

Re-enrollment MUST NOT occur automatically as part of RESTORE, install, repair, service start, retry, or error handling.

It may proceed only after BOTH conditions are met:

1. Reconciliation with Central has resolved the previous registration outcome and established the safe disposition of the old Agent/application registrations.
2. An authorized operator has explicitly approved re-enrollment for the affected server/Agent after reviewing that reconciliation result.

The authorization MUST be deliberate and attributable to the operator/change record. A retry, rerun of the installer, newly generated token, timeout, or missing local file is not authorization.

If Central cannot establish a safe disposition for the old registration, the operation remains blocked. Do not create a second identity to work around the uncertainty.

## 4. Separation of RESTORE and re-enrollment

RESTORE means recovering the existing verified Agent identity and its required local integration artifacts. RESTORE MUST preserve the existing Agent instance ID, Central Agent ID, Server ID, application registrations, and credentials.

Re-enrollment is a separate, explicitly authorized lifecycle operation. It MUST NOT be disguised as RESTORE or performed as an implicit fallback when RESTORE fails.

## 5. Audit and implementation requirements

Implementations and operator procedures MUST retain enough non-secret evidence to explain:

- The verification failure that caused recovery-required status.
- The Central reconciliation result and the registrations covered.
- The explicit authorization and its operator/change reference.
- The resulting recovery or re-enrollment outcome.

This policy does not define a key-rotation protocol, integrity-key backup format, cryptographic state migration procedure, or detailed Central API contract. Those remain separate design decisions and MUST be specified and reviewed before implementation. No implementation may weaken the fail-closed sequence while those details remain open.

## 6. Acceptance criteria

The policy is satisfied only when tests and operational evidence demonstrate that:

- Existing state with a missing or invalid integrity key fails closed without key regeneration.
- Invalid or mismatched identity never causes automatic identity replacement.
- Uncertain enrollment never triggers automatic token retry or re-enrollment.
- RESTORE preserves the existing identity and does not enroll a replacement identity.
- Re-enrollment remains blocked until Central reconciliation and explicit authorization are both recorded.
- Recovery diagnostics contain no credentials or other secret material.