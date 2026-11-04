# PHP2Shell Fix command reference

[Documentation index](README.md) · [Quick start](../README.md#quick-start) · [FAQ](frequently-asked-questions.md)

The executable is `php2shell-fix` on Linux and `php2shell-fix.exe` on Windows. Commands inspect local PHP **CLI** executables; they do not establish the state of an active PHP-FPM, Apache or IIS worker. Run only trusted PHP executables: inspection starts the selected CLI and can load its locally configured extensions.

## Commands and required arguments

Run one action at a time. `scan`, `verify` and `report` also accept the subcommand forms shown below; the other actions use flags. `PATH`, `INI_PATH` and `BACKUP_ID` are placeholders to replace with your verified values.

| Action | Invocation | Behavior |
| --- | --- | --- |
| Inventory and assess | `php2shell-fix scan [--php PATH] [--json]` | Read-only CLI discovery and version-based findings. Omitting an action also scans. |
| JSON assessment | `php2shell-fix report [--php PATH]` | Same inventory and assessment, always emitted as JSON. `--report` is equivalent. |
| APT update plan | `php2shell-fix --plan-update --php PATH` | Read-only native Debian/Ubuntu package checks and APT simulation. Always emits JSON. Requires a package-owned PHP CLI on Linux. |
| Preview mitigation | `php2shell-fix --dry-run --php PATH --ini INI_PATH [--json]` | Checks the selected CLI and matching loaded INI; does not write configuration or create backups. |
| Apply mitigation | `php2shell-fix --apply --php PATH --ini INI_PATH [--json]` | Appends `session.upload_progress.enabled=Off` to the selected CLI-loaded INI with a protected backup and post-change CLI check. An already-disabled setting is a no-op. |
| Verify mitigation | `php2shell-fix verify --php PATH [--json]` | Read-only inspection of the selected CLI's effective session setting. `--verify` is equivalent. |
| Restore backup | `php2shell-fix --rollback BACKUP_ID` | Restores one tool-created configuration backup after integrity and target checks. Emits a plain-text result. |

`--apply` changes only the explicitly selected configuration; it does not install a PHP security release or restart services. Review application compatibility and your change procedure first. See [mitigation instructions](../README.md#apply-the-conditional-session-mitigation) and [rollback constraints](rollback.md).

## Path and output options

- `--php PATH`: exact trusted PHP CLI executable to inspect. Required for update planning, dry-run, apply and verify; optional for scanning and reporting.
- `--ini INI_PATH`: the INI actually loaded by that CLI. Required for dry-run and apply. A mismatch is refused; this is not a way to edit an unrelated FPM or IIS configuration. Do not supply `--ini` with `--plan-update`; that combination is refused.
- `--state-dir PATH`: private backup directory for apply and rollback. The default is `~/.php2shell-fix/`. Use the same directory when restoring its backups. Read-only actions do not require HOME to resolve this default. Existing state and ancestor permissions are checked, not silently repaired.
- `--json`: structured output for scan, dry-run, apply and verify. Report and update-plan actions already emit JSON. Rollback does not emit JSON, even if this flag is supplied.
- `--help`: displays built-in usage and flags. The current CLI returns exit code `3` after displaying help; this is not a vulnerability finding.

Paths with spaces must be quoted using your shell's syntax. On Windows PowerShell, invoke a locally built executable as `.\php2shell-fix.exe`.

## Read-only examples

Scan one explicit Linux PHP CLI and keep the JSON report in a controlled directory:

```bash
./php2shell-fix scan --php /usr/bin/php --json > php2shell-report.json
```

Inspect a native Debian/Ubuntu package update candidate without installing it:

```bash
./php2shell-fix --plan-update --php /usr/bin/php --json
```

Verify only the session mitigation setting of an explicit Windows PHP CLI:

```powershell
.\php2shell-fix.exe --verify --php C:\php\php.exe --json
```

These example paths are not auto-detected facts about your host. Reports can contain filesystem paths and environment details; review and redact them before sharing.

## Output and exit codes

**Exit code `0` is not a security verdict.** Interpret the action, top-level status, per-installation errors and vulnerability findings together.

| Action | Exit behavior | What must still be checked |
| --- | --- | --- |
| Scan / report | `0` after reporting, including findings, individual inspection errors or no PHP CLI found | Top-level `status`, each installation's `error` and `findings`, vendor patch evidence and actual serving workers |
| Update plan | `0` for a completed plan, even if inconclusive; `3` if prerequisites or an operation fail | Plan eligibility and reasons, package provenance, vendor advisories and administrator approval |
| Dry-run / apply / rollback | `0` when completed or apply is a no-op; `3` on refusal or operational failure | Action result, backup ID where created, affected application and independent web-worker checks |
| Verify | `0` with `CLI_MITIGATION_VERIFIED`; `2` with `CLI_MITIGATION_NOT_APPLIED`; `3` if inspection or required evidence fails | Only the selected CLI session setting was checked; neither PHP core patching nor web workers were verified |

For JSON inventory reports, `status: "ASSESSMENT_ONLY"` describes an assessment, not a pass. `NO_PHP_CLI_FOUND` means discovery found no candidate; on Windows, `IIS_CONFIG_ONLY_NO_PHP_CLI` can indicate configured IIS bindings without a discovered CLI. Individual installation errors must not be treated as clean findings.

For verify output, an explicitly reported empty `upload_progress` string is PHP's disabled value; it is not a missing field. A missing effective setting, missing loaded INI or uninspectable CLI fails verification. Read [vulnerability coverage](vulnerability-coverage.md) for finding statuses such as `UPSTREAM_FIXED` and `VENDOR_REVIEW_REQUIRED`.

## Sources of truth

The [CLI implementation](../cmd/php2shell-fix/main.go) defines argument handling and output behavior. [Architecture](architecture.md), [supported environments](supported-environments.md) and [backup and recovery](rollback.md) define the implementation's safety boundaries. Keep a release tag or exact commit with reports so that commands, source and evidence refer to the same version.
