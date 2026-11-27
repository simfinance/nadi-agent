# NADI Agent — Supported installation targets

## Scope defined by the approved NADI Master Rule

NADI Agent is designed to be installed once per server and to serve multiple Laravel applications on that server. The supported server baseline is:

| Dimension | Supported baseline |
|---|---|
| Operating system | Ubuntu Linux |
| Init/service manager | systemd |
| CPU architecture | Linux AMD64 (amd64, x86_64) |
| CPU architecture | Linux ARM64 (arm64, aarch64) |
| Runtime identity | Dedicated non-root user nadi-agent |
| Agent count | One Agent per server |
| Application count | Multiple Laravel applications per Agent, subject to enrollment limit and per-app isolation |

The Agent provisioning helper checks host OS, architecture, Ubuntu distribution ID, and systemd availability before making provisioning changes. Unsupported platforms fail before the provisioning lock or filesystem mutations are attempted.

This is provider-neutral: the server may be hosted by any infrastructure provider or belong to any customer environment, provided it meets the supported Ubuntu/systemd/architecture baseline and infrastructure prerequisites. It is not a claim of support for every operating system or Linux distribution.

## Application compatibility

The approved pilot compatibility baseline is Laravel 10 with PHP 8.2. Other Laravel/PHP combinations must pass compatibility tests before they are declared supported.

The intended application installation experience is:

```bash
composer require nadi/laravel-agent
php artisan nadi:install
```

The Composer package must auto-register its service provider, routes, controllers, middleware, commands, and listeners. Developers must not be required to create monitoring routes/controllers manually or install Go, Python, Node.js, exporters, or other monitoring software.

**Repository boundary:** the Composer package is maintained separately in [simfinance/nadi-laravel-agent](https://github.com/simfinance/nadi-laravel-agent); this Go repository contains the Agent and provisioning implementation, not the PHP package. The PHP package declares the Composer name `nadi/laravel-agent` and is distributed through the private NADI Composer repository. Its `nadi:install` command verifies and stages the signed release artifact, then invokes only the fixed root-owned helper through non-interactive sudo. The helper must already be installed through the trusted OS bootstrap package; Composer never installs or replaces it.

Private Composer repository discovery and authentication must be provisioned by the deployment administrator before `composer require`. Do not place Composer tokens in the application repository, `.env`, shell history, or application files. The exact Private Packagist organization slug and credentials must come from the authorized account; never guess them.

Before the deployment user runs Artisan, the server administrator must install the signed architecture-specific `nadi-provision-helper` Debian package through the trusted OS package channel and configure the exact helper-only sudoers authorization. Artisan and Composer must never run as root. The helper package build, content validation, and signature-verification source are present, but production signing/publication and disposable Ubuntu integration remain incomplete.

The package's declared Illuminate constraints are broader than the approved pilot baseline. They must not be treated as a compatibility guarantee until the corresponding Laravel/PHP combinations pass the package test matrix.

## Server prerequisites

- Ubuntu Linux with systemd and a supported CPU architecture.
- Permission to perform narrowly scoped provisioning operations through the approved installer/helper.
- Outbound HTTPS connectivity to the configured NADI Central URL; TLS 1.2 minimum and TLS 1.3 preferred.
- A valid NADI enrollment token and the Central Activation Grant public key distributed through the approved trust process.
- Sufficient disk and memory capacity for the selected Agent release and configured spool limits.
- Infrastructure-managed network routing, DNS, firewall, and Central source-IP allowlisting where required.

The installer must stop with a diagnosis if a prerequisite is missing. It must not modify Nginx, firewall, PHP-FPM, Supervisor, application configuration, or business services without an explicitly authorized operation.

## Multi-application behavior

- One Agent is installed on a server, not one Agent per Laravel application.
- Adding another Laravel application registers it with the existing Agent.
- Server metrics are collected once per server.
- Application metrics, credentials, endpoint, activation grant, and spool are scoped per application.
- Suspending or revoking one application must not stop another application's valid monitoring.
- No application probe, collector, or telemetry is allowed before that application's valid Activation Grant.

## Explicitly unsupported until separately approved and tested

- Windows and macOS.
- Non-Ubuntu Linux distributions.
- Linux architectures other than AMD64 and ARM64.
- Hosts without systemd.
- Laravel/PHP combinations outside the tested compatibility matrix.
- Automatic changes to Nginx, firewall, PHP-FPM, Supervisor, or application business configuration.

## Release readiness

The platform preflight is not proof of a production release. A deployable release still requires signed/checksummed AMD64 and ARM64 artifacts, a published release manifest, a fully connected Composer Bridge installer and privileged provisioning adapter, installation/update/repair/uninstall tests, multi-application isolation tests, and live Agent-to-Central E2E validation. Do not install unsigned or unverified binaries.
