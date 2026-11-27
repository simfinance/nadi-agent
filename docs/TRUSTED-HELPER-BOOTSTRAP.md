# Trusted Provisioning Helper Bootstrap Boundary

Status: Debian bootstrap package source and CI installation checks are implemented. Production package signing/publication and supported-host integration remain release gates.

## Fixed executable contract

The privileged entrypoint is fixed at:

```text
/usr/libexec/nadi/nadi-provision
```

The executable accepts only:

```bash
nadi-provision --request-stdin
```

The request remains JSON on standard input. The helper does not accept an operation name, command path, service name, destination path, or arbitrary filesystem target through argv.

## Trust model and first-install bootstrap

The deployment user cannot install a root-owned executable by itself, and Composer must not cross that privilege boundary. Therefore, the first helper installation is performed by the server administrator through the trusted Ubuntu OS package channel before the deployment user runs Artisan.

The bootstrap package is named `nadi-provision-helper`. It is an architecture-specific Debian package containing exactly one file:

- `/usr/libexec/nadi/nadi-provision`

The package contains no maintainer scripts, service units, configuration files, credentials, or additional executables. Its helper file is root:root mode 0755. Package construction uses `dpkg-deb --root-owner-group` and validates the source Agent binary against the SHA-256 digest supplied by the signed release manifest.

The release process must produce a detached Ed25519 signature over the complete `.deb` package using the existing NADI Agent release signing key. The server administrator must obtain the public key through the established trusted distribution channel and verify its pinned fingerprint before use:

```text
91d063a323ffb7feaad3e4bf39d750ec339b2206b74f762d11e1f291267a49e1
```

Verify the package signature before installation:

```bash
scripts/verify-helper-package-signature.sh \
    /path/to/trusted-release-signing-public.pem \
    nadi-provision-helper_VERSION_ARCH.deb \
    nadi-provision-helper_VERSION_ARCH.deb.sig
```

After successful verification, the server administrator installs the package through the OS package manager:

```bash
sudo dpkg -i nadi-provision-helper_VERSION_ARCH.deb
```

The package has no pre-install, post-install, pre-remove, or post-remove scripts. It only places the already signed helper executable at its fixed root-owned path. This bootstrap step is administrator-managed OS provisioning, not Composer execution and not a monitoring collector installation.

The package must be updated to the exact Agent release version before running an Agent update. The helper's journaled asset installer rejects a conflicting existing helper binary; it does not silently replace an independently installed package-owned helper.

## One signed binary for Agent and helper

The helper entrypoint is a second invocation mode of the same `cmd/nadi-agent` executable verified by the existing Ed25519 release manifest.

The installer installs the verified artifact at:

- `/opt/nadi/bin/nadi-agent`
- `/usr/libexec/nadi/nadi-provision`

The second file must be byte-for-byte identical to the verified artifact. The Debian bootstrap package uses that same binary and must be built from the same release output. The helper is not an independently trusted executable or unsigned secondary build.

The executable selects helper mode only when invoked with the `nadi-provision` basename. It validates its resolved executable path against the fixed helper path before reading or dispatching the request. Invoking the same binary under the Agent name continues to use the normal Agent CLI.

## Runtime self-validation

Before dispatching a privileged request, the executable validates its own resolved path against the fixed installation path. The validation rejects:

- an executable launched from any other path;
- a symlinked executable or symlinked parent path;
- a non-regular executable;
- an executable not owned by root;
- group/other-writable executable or parent directories;
- an executable without execute permission;
- setuid or setgid bits on the helper executable.

The helper reuses the trusted command path validator for the parent-directory chain. The check is an additional runtime guard; package authenticity is established by the detached signature verified by the administrator before installation.

## Deployment-user invocation and sudoers

Laravel, Composer, Artisan, service providers, and package-owned writable files must run as the application deployment user, never as root. In particular, do not run `composer require` or `php artisan nadi:install` with `sudo` or from a root shell.

The deployment user invokes the fixed helper only through:

```text
/usr/bin/sudo -n -- /usr/libexec/nadi/nadi-provision --request-stdin
```

The server administrator must create a sudoers entry for the exact Unix account that runs `php artisan nadi:install`:

```sudoers
<installer-user> ALL=(root) NOPASSWD: /usr/libexec/nadi/nadi-provision --request-stdin
```

Replace `<installer-user>` with the verified deployment account. The sudoers file must be root-owned, mode 0440, and validated with `visudo -cf`. Do not grant a wildcard, shell, general root command, arbitrary executable argument, or package-manager command through sudoers.

The Bridge rejects UID 0 before downloading the Agent release or invoking the helper. The package never requests, stores, or forwards a sudo password. Interactive sudo prompting is not supported. The PHP-FPM runtime identity remains separate from the installer caller and from the `nadi-agent` service identity.

## Fixed helper protocol

The helper accepts only:

```bash
nadi-provision --request-stdin
```

The request is one bounded JSON document on standard input. The helper rejects unknown fields, unknown operations, duplicate JSON keys, trailing JSON values, oversized input, and unsupported protocol versions.

Protocol version 1 exposes three operation-specific request envelopes:

- `install_agent`: verify and install only; no enrollment token.
- `enroll_agent`: one complete application manifest and one-time token on standard input; enrollment runs as `nadi-agent`.
- `start_agent`: enable/start only the fixed NADI units after verifying registration and broker completion.

An uncertain enrollment result remains non-retryable until reconciled. The helper never accepts caller-selected commands, units, users, groups, filesystem destinations, or permissions.

## Validation

The Agent CI builds AMD64 and ARM64 bootstrap packages from the corresponding Agent binary, verifies package metadata and exact contents, rejects all maintainer scripts, installs each package on an Ubuntu runner, and checks the installed helper is root:root mode 0755 before removing the test package.

The CI package is a validation artifact, not a production release. Production release remains blocked until:

- the release process signs each package with the trusted Ed25519 release key;
- the detached signature and public-key distribution are independently verified;
- the signed packages are published through the approved distribution channel;
- the exact sudoers rule is validated with `visudo -cf`;
- root/non-root and systemd integration tests pass on supported disposable Ubuntu hosts;
- the complete Composer, Artisan, helper, Agent, Broker, Bridge, Central enrollment, approval, Activation Grant and acknowledgement flow passes end-to-end.

No production host, Central service, customer application configuration, firewall, or monitoring activation is modified by these package build tests.
