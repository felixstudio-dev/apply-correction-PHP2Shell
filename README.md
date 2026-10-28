# PHP2Shell Fix — PHP Security Assessment and Safe Configuration Mitigation

**Project status: early security tooling preview.** This repository contains a working PHP CLI inventory and assessment tool, a read-only native APT update planner, and a reversible configuration mitigation for a conditional PHP session vulnerability. **It does not automatically install the PHP security releases that fix the two critical PHP2Shell CVEs.** Never treat a successful scan or configuration mitigation as proof that a web server is patched.

PHP2Shell is a name used for two critical October 21, 2026 PHP remote-code-execution issues: **CVE-2026-109618** (out-of-memory corruption) and **CVE-2026-109619** (stale request-global state). The PHP project released fixed upstream versions **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Upgrading to an official patched build or a verified vendor-backported package is required; mitigations are incomplete. A separate conditional issue, **CVE-2026-115560**, involves session upload progress and unusual application runtime configuration. The PHP project recommends disabling `session.upload_progress.enabled` until the upcoming regular release. [Official PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) · [PHP's session advisory](https://www.php.net/archive/2026.php#2026-10-23-1).

## Quick start

Prerequisites: Go 1.27+ for source builds; PHP installed locally for live CLI inspection. The tool has **no runtime third-party dependencies** and does not send host inventory or configuration contents to external services.

```bash
git clone https://github.com/felixstudio-dev/apply-correction-PHP2Shell.git
cd apply-correction-PHP2Shell
go build -o php2shell-fix ./cmd/php2shell-fix
./php2shell-fix scan
./php2shell-fix --report > php2shell-report.json
```

Windows PowerShell:

```powershell
go build -o php2shell-fix.exe ./cmd/php2shell-fix
.\php2shell-fix.exe scan --json
```

On an apt-managed Debian/Ubuntu host, inspect an explicit, package-owned CLI and produce a **read-only** update plan:

```bash
./php2shell-fix --plan-update --php /usr/bin/php --json
```

This checks installed branch packages, compares APT candidates with the official upstream patch floor, inspects the candidate repository host, and runs an APT **simulation** (`apt-get -s`). A candidate from an unfamiliar mirror or below the upstream floor is flagged for manual vendor-advisory verification. `ELIGIBLE_FOR_ADMIN_REVIEW` still requires administrator review of release notes, service restarts, backups and application compatibility. **The preview does not execute `apt-get install`**, and vendor backport validation is intentionally not inferred from package version strings. Read [Linux upgrade planning](docs/php2shell-linux.md) before acting on a preview command.

The default action and `scan` are read-only. The tool searches PATH and selected standard installation directories for PHP **CLI** executables, runs a bounded PHP introspection command, and prints version-based findings. **A CLI runtime is not necessarily the PHP worker serving a site.** Docker, IIS, PHP-FPM, Apache modules, hosting panels, distribution backports and other installations require additional verification.

`scan --json` additionally reports the detected operating-system family, distribution, package-manager availability and precisely scoped update-planning capability. This includes CentOS Linux/Stream and other recognized Linux families, plus Windows Server classification from the OS registry. On Windows, the `iis` report reads configured PHP FastCGI applications and handler mappings in the standard IIS global configuration file, when accessible; all discovered bindings are `CONFIGURED_ONLY`. Distribution recognition is `DETECTION_ONLY` unless the specific native Debian/Ubuntu APT read-only planning prerequisites are met. Effective Windows Server/IIS FastCGI worker verification and automatic PHP binary upgrades remain unimplemented.

## Security coverage

| Vulnerability | Current implementation | Recommended correction |
| --- | --- | --- |
| CVE-2026-109618 | Version-based upstream status; vendor-backport uncertainty reported | Official fixed PHP release or vendor-patched package; verify active workers |
| CVE-2026-109619 | Version-based upstream status; vendor-backport uncertainty reported | Official fixed release or verified vendor package; upload-progress mitigation alone is insufficient |
| CVE-2026-115560 | Conditional-risk finding and reversible `php.ini` mitigation | Disable session upload progress in the active server context until the vendor fix is available |

Version status `UPSTREAM_FIXED` means the reported PHP version meets the upstream release floor; it **does not** establish binary provenance, a patched web worker, or a vendor patch audit. An older distribution package can contain security backports. No CVE exploitation probes are performed.

### Preview an explicit configuration mitigation

Choose the PHP executable and its actual loaded `php.ini`; confirm these paths before making changes.

```bash
./php2shell-fix --dry-run --php /usr/bin/php --ini /etc/php/8.4/cli/php.ini
```

```powershell
.\php2shell-fix.exe --dry-run --php C:\php\php.exe --ini C:\php\php.ini
```

### Apply the conditional session mitigation

**Only after checking compatibility with your application and authorizing downtime**. PHP upload-progress features may stop working. The tool appends `session.upload_progress.enabled=Off` to the explicitly selected `php.ini`, creates a private integrity-checked backup, validates the inspected **CLI** configuration and returns a backup ID. It does not restart any service. It will refuse the change if the supplied `php.ini` does not match the loaded configuration reported by the selected executable.

```bash
./php2shell-fix --apply --php /usr/bin/php --ini /etc/php/8.4/cli/php.ini
./php2shell-fix --verify --php /usr/bin/php
./php2shell-fix --rollback BACKUP_ID
```

`--verify` requires an explicit PHP CLI path and reports `CLI_MITIGATION_VERIFIED` only if that CLI can be inspected and reports session upload progress disabled. `CLI_MITIGATION_NOT_APPLIED` means it is still enabled. In JSON, `upload_progress: ""` is the actual disabled value returned by PHP's `ini_get`; it is retained rather than omitted. These results are limited to the selected **CLI**, not PHP-FPM, Apache or IIS workers.

After application, restart **only the relevant PHP workers under your own change procedure**, check each web-serving SAPI's effective settings and health, and install the official PHP security release for CVE-2026-109618/109619. **Do not assume the CLI `php.ini` controls PHP-FPM, Apache or IIS.** For production FPM, you will usually need to configure its separately loaded INI or pool settings and verify those directly. This release deliberately does not automate server restarts or package upgrades.

Backups are stored under `~/.php2shell-fix/`, protected with user-only permissions on POSIX and a restricted current-user ACL on Windows. Rollback validates the saved SHA-256 and refuses to overwrite independently modified configuration. A stale `.lock` file after a crash requires manual inspection before removal. See [backup and recovery](docs/rollback.md).

## Exit codes and machine-readable output

`0` = command completed (findings can still require action; for `--verify`, the selected CLI reports the mitigation disabled); `2` = `--verify` found session upload progress enabled in the selected CLI; `3` = refused action, incomplete verification or operational error. Structured reports support `--json` and `--report`; see [vulnerability coverage](docs/vulnerability-coverage.md) for status semantics. Reports contain filesystem paths and potentially sensitive environment details: store them in a controlled location.

## Compatibility and limitations

| Environment | Current status | Evidence |
| --- | --- | --- |
| Windows 11 x64, PHP CLI | PARTIALLY_SUPPORTED | Native Windows amd64 CLI scan and `--verify` passed against PHP 8.4.27 on October 27, 2026; reported `CLI_MITIGATION_VERIFIED` only for that CLI and `CONFIG_NOT_FOUND` for IIS. No live IIS/FastCGI worker evidence |
| Windows 10 client | DETECTION_ONLY; physically UNTESTED | Registry-based client classification and compiled builds; no site-worker evidence |
| Windows Server 2016 / 2019 / 2022 x64, PHP CLI | PARTIALLY_SUPPORTED (CLI configuration mitigation only) | Physical VirtualBox tests on October 27, 2026 passed scan, dry-run, configuration mitigation, verification, idempotency, SHA-256-checked rollback and restored verification using PHP 8.5.12 CLI (NTS); IIS and PHP-core patching were not tested |
| Windows Server 2025 x64, PHP CLI | DETECTION_ONLY; physical remediation UNTESTED | Physical CLI remediation remains pending; completed guest-control and end-to-end remediation evidence has not yet been recorded |
| Windows Server / IIS FastCGI | DETECTION_ONLY for IIS | Registry-based Server identification and read-only global IIS FastCGI configuration discovery; effective worker and remediation validation pending |
| Linux x64, PHP CLI | PARTIALLY_SUPPORTED (selected CLI mitigation) | Ubuntu 24.04 WSL2 binary and unit checks; real PHP 8.2.35 CLI mitigation, verification, and hash-checked rollback passed in a disposable Debian 12 container. No active web worker or package upgrade tested |
| Ubuntu/Debian PHP | PARTIALLY_SUPPORTED for native read-only APT planning | Exact package provenance and compatible official security candidate still require independent admin review |
| CentOS Linux/Stream, RHEL, Rocky, AlmaLinux, other RPM systems | DETECTION_ONLY | CentOS container scan identified `yum`; other RPM variants require independent validation. No RPM upgrade automation or vendor backport attestation |
| Other Linux distributions (SUSE, Arch, Alpine, Gentoo, NixOS, Void, etc.) | DETECTION_ONLY | Best-effort PHP CLI scan and OS/package-manager identification; vendor update path unverified |
| Docker, Plesk, cPanel and shared hosting | UNSUPPORTED for mutation | Use vendor/container image update procedures |

See [supported environments](docs/supported-environments.md), [architecture](docs/architecture.md), [Windows guidance](docs/php2shell-windows.md), [Linux guidance](docs/php2shell-linux.md), [Docker guidance](docs/php2shell-docker.md), and [FAQ](docs/frequently-asked-questions.md). Platform rows are updated only when supported by reproducible evidence; compilation alone is not physical validation.

## Verify and contribute

```bash
go test ./...
go vet ./...
go build ./cmd/php2shell-fix
```

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability, [CONTRIBUTING.md](CONTRIBUTING.md) before contributing, and [CHANGELOG.md](CHANGELOG.md) for the implemented release scope. Licensed under [MIT](LICENSE). The project is independent and is not affiliated with or endorsed by the PHP project or public security agencies.

## Authoritative references

- [PHP Security Advisory — October 21, 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP Session Upload Progress Advisory — October 23, 2026](https://www.php.net/archive/2026.php#2026-10-23-1)
- [PHP GHSA-w8hw-w9fx-j79w — CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP GHSA-6wmf-4rv5-p3rp — CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP Windows downloads](https://windows.php.net/download/)

**Maintainer:** [Felix Studio Developer](https://github.com/felixstudio-dev). No official CVE certification or universal remediation guarantee is implied.
