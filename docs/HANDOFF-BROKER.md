# NADI Agent-to-Bridge Handoff Broker

Status: implementation foundation; not production-installed or deployment-approved.

## Runtime boundary

The broker runs in a dedicated mode of the signed NADI Agent release binary through a separate root-owned systemd service. It is not started by Composer and is not run as part of the Laravel PHP process. The helper installs the same verified binary at the fixed Agent path; systemd invokes its `--handoff-broker` mode. It accepts only local Unix-domain socket connections at:

`/run/nadi-agent/credential-handoff.sock`

The broker authenticates the connecting process using Linux `SO_PEERCRED` and compares the kernel-reported UID with the root-owned mapping configuration's `agent_uid`. It never trusts a UID supplied in JSON.

## Mapping configuration

The root-owned file `/etc/nadi-agent/bridge-mappings.json` uses schema version 1:

```json
{
    "schema_version": 1,
    "agent_uid": 1001,
    "agent_gid": 1001,
    "applications": [
        {
            "application_id": "central-application-id",
            "application_key": "stable-bridge-application-key",
            "base_path": "/srv/www/example",
            "runtime_uid": 33,
            "runtime_gid": 33,
            "credential_file": "/var/lib/nadi-bridge/central-application-id/credential",
            "activation_state_file": "/run/nadi-agent/bridge-state/example.json"
        }
    ]
}
```

The numeric runtime UID/GID must be discovered from the actual Laravel PHP-FPM pool. The example UID/GID 33 represents a common `www-data` installation only; it is not a universal default. Mapping file owner/group must be `root:root`, mode `0600`, and its parent directory must be root-owned and not group/other writable. The file is bounded to 16 KiB.

## Operations

- `publish_application_credential`: writes only to the registered application's exact credential destination, owner `runtime_uid:runtime_gid`, mode `0600`.
- `publish_activation_state`: writes the Agent's effective state lease to the registered activation assertion destination, owner `root:runtime_gid`, mode `0640`.

Both writes use a same-directory temporary file, fsync, atomic rename, and directory fsync. Destination symlinks and non-regular existing files are rejected. Request size is limited to 16 KiB; response size is limited to 4 KiB. Duplicate JSON keys, unknown fields, trailing JSON values, unsupported versions, and unapproved capabilities are rejected.

The broker preserves Central grant capability names. Bridge endpoint mapping is performed by the Laravel Bridge using the separately approved mapping table. `server_metrics` does not authorize a Bridge endpoint.

## Runtime directories and permissions

- Socket directory: `/run/nadi-agent`, owner `root:root`, mode `0711`. Execute-only access lets the PHP runtime traverse to its assertion file without granting socket access.
- Socket: owner `root:nadi-agent`, mode `0660`.
- Activation state directory: `/run/nadi-agent/bridge-state`, owner `root:root`, mode `0711`.
- Activation assertion: owner `root:<Laravel runtime group>`, mode `0640`.
- Credential parent directory: `/var/lib/nadi-bridge/<application_id>`, root-owned mode `0711`; the Laravel runtime can traverse but cannot replace the directory or list its contents.
- Application credential: owner `<Laravel runtime user>:<Laravel runtime group>`, mode `0600`.

The Laravel runtime can traverse the activation-state directory and read only its configured assertion file. It cannot list the directory or write assertions. The Agent can connect to the socket but cannot read the root-owned mapping file.

## Current limitations / install gate

The base broker unit grants write access only to `/run/nadi-agent`. The privileged installer must add a root-owned systemd drop-in with `ReadWritePaths=` entries for the exact registered `/var/lib/nadi-bridge/<application_id>` credential directories; it must not grant broad write access to `/var/lib/nadi-bridge`, `/srv`, or another shared application root. This foundation does not yet include the privileged helper, root-owned mapping-file generation, application path canonicalization at install time, systemd drop-in generation/enablement, rollback, or end-to-end Agent/Bridge/broker tests. The service unit is a source artifact only and must not be installed manually yet.

The installer must remain fail-closed. Do not deploy this broker or enable Bridge monitoring until the remaining installation and integration gates pass.


## Credential path hardening checkpoint

The broker mapping validator now rejects credential destinations inside Laravel application trees and accepts only:

`/var/lib/nadi-bridge/{application_id}/credential`

This prevents an application runtime user from replacing a credential file through a writable application parent directory. The broker systemd source unit must keep its base write scope limited to `/run/nadi-agent`; the future helper is responsible for generating an exact per-application `ReadWritePaths=` drop-in.

**Integration dependency:** the current Laravel Bridge package configuration still defaults to `storage/app/private/nadi/credential`. Bridge must be changed to resolve the external path before this broker mapping can be used end-to-end. Until that is done, credential handoff is intentionally not production-ready.
