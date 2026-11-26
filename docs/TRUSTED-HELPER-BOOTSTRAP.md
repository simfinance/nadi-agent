# Trusted Provisioning Helper Bootstrap Boundary

Status: partial implementation. This document does not authorize production installation or sudoers deployment.

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

## Runtime self-validation

Before dispatching a privileged request, the executable validates its own resolved path against the fixed installation path. The validation rejects:

- an executable launched from any other path;
- a symlinked executable or symlinked parent path;
- a non-regular executable;
- an executable not owned by root;
- group/other-writable executable or parent directories;
- an executable without execute permission;
- setuid or setgid bits on the helper executable.

The helper reuses the trusted command path validator for the parent-directory chain. The check is an additional runtime guard; it does not install the helper or establish the trustworthiness of a package source.

## What remains intentionally unimplemented

- No package or release artifact currently installs the helper at the fixed path.
- No Composer script installs, replaces, or invokes the root-owned helper.
- No sudoers file is generated or installed.
- No caller principal or shared privilege group is inferred. The exact PHP-FPM/Artisan execution identity and narrow sudoers rule require an approved runtime identity contract.
- No privileged-host installation or systemd integration test is claimed.

The helper must not be exposed through a wildcard sudoers rule, a caller-selected executable, or a broad command alias. A future package must install the binary as root, preserve the fixed path and permissions, and be verified independently of Composer.

## Validation scope

Unit tests cover the executable path validator with temporary fixtures. The standard Go CI workflow must still pass for the implementation commit. These tests do not replace package installation tests, sudo authorization tests, root/non-root integration tests, or disposable Ubuntu end-to-end tests.
