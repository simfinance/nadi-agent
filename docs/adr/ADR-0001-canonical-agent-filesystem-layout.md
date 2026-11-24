# ADR-0001: Canonical NADI Agent Filesystem Layout

- Status: Accepted
- Date: 2026-11-24
- Scope: NADI Agent and Laravel Bridge integration
- Authority: NADI Master Architecture Technical Specification v1.0, section 10.4; NADI Agent Side Monitoring Specification v1.0

## Context

The Master Architecture defines the baseline filesystem locations for NADI:

- `/opt/nadi`
- `/etc/nadi`
- `/var/lib/nadi`
- `/var/log/nadi`
- `/run/nadi`

It also requires final locations and ownership to be tested by the installer and states that the Agent runtime must not run as root. The Agent Side Monitoring Specification requires a dedicated non-root system user named `nadi-agent`; root/sudo is limited to installer provisioning.

The implementation had accumulated Agent-specific path variants. A single canonical layout is needed so the Agent binary, configuration, state, logs, runtime sockets, systemd units, broker artifacts, tests, and documentation remain consistent.

## Decision

Adopt the five filesystem locations in Master Architecture section 10.4 as the canonical Agent layout. Do not establish parallel permanent `-agent` directory roots or symlink-based compatibility paths.

Use the following logical layout:

| Purpose | Canonical location |
| --- | --- |
| Agent binary and provisioner | `/opt/nadi/bin/` |
| Agent configuration and broker mappings | `/etc/nadi/` |
| Persistent Agent state | `/var/lib/nadi/state/` |
| Agent spool | `/var/lib/nadi/spool/` |
| Engine files | `/var/lib/nadi/engines/` |
| Agent logs | `/var/log/nadi/` |
| Credential handoff socket | `/run/nadi/credential-handoff.sock` |
| Per-application activation state | `/run/nadi/bridge-state/{application_id}.json` |

The Laravel Bridge credential remains outside the Laravel application tree and outside the Agent's general state directory:

`/var/lib/nadi-bridge/{application_id}/credential`

The credential location is a deliberate per-application security boundary. The application UUID must be issued by Central and validated by the Agent; callers must not choose arbitrary credential destinations.

The Agent runtime continues to run as the dedicated non-root `nadi-agent` user. Root-owned provisioning remains limited to the installer/provisioning helper and only to the filesystem and service operations required for installation.

## Permission and ownership policy

The specifications require installer verification of final locations and ownership; they do not prescribe every numeric mode. Therefore, proposed modes such as `0750`, `0711`, and `0600` are implementation defaults, not claims about explicit source requirements.

The installer must validate ownership, modes, path components, symlink handling, and runtime access. It must not silently alter Nginx, firewall, PHP-FPM, Supervisor, or client application configuration. Any required deviation must be documented and tested.

## Consequences

- Agent code, embedded systemd assets, broker configuration, installer logic, tests, and documentation must use this canonical layout consistently.
- Bridge configuration and activation-state validation must agree with the same paths.
- No Central repository changes are authorized or required by this ADR; Central remains read-only.
- Migration must not introduce dual-path fallback or silently move existing state. Existing installations require an explicit, safe migration/recovery strategy before any production migration.
- Installer tests must verify final directory ownership and permissions on supported platforms.

## Source alignment

This decision adopts the baseline locations directly from Master Architecture section 10.4 and preserves the non-root runtime and restricted installer privilege model in the Agent Side Monitoring Specification. The subdirectory layout and numeric permission defaults above are implementation decisions and remain subject to installer validation.
