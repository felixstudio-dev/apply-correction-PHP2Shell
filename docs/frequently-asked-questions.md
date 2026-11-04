# PHP2Shell: Frequently Asked Questions

[Documentation index](README.md) · [Command reference](command-reference.md)

## What is PHP2Shell Fix?

PHP2Shell Fix is the independent open-source Go CLI in [felixstudio-dev/apply-correction-PHP2Shell](https://github.com/felixstudio-dev/apply-correction-PHP2Shell), maintained by Felix Studio Developer. Its executable is named `php2shell-fix`. It inventories local PHP CLI installations, provides read-only Debian/Ubuntu APT update planning, and can mitigate a separate session configuration issue for one selected CLI. It is not an official PHP project tool or a universal PHP patch installer.

## What is PHP2Shell?

PHP2Shell refers to the October 2026 critical PHP remote-code-execution disclosures CVE-2026-109618 and CVE-2026-109619. See the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5).

## How do I fix PHP2Shell?

Install an official fixed PHP release (8.2.35, 8.3.36, 8.4.27 or 8.5.12) or a vendor-verified backported package, then restart and verify every relevant PHP worker. The tool cannot currently perform those upgrades.

## How can I check whether PHP is vulnerable?

Run `php2shell-fix scan --json` for an initial CLI inventory, then check active web workers and authoritative vendor patch metadata. A version scan does not prove exposure or absence of risk.

## Does exit code 0 mean my web server is safe?

No. A scan can complete with findings, failed CLI inspections, or no PHP CLI found. Inspect the JSON report status, each installation's error and findings, and verify actual serving workers separately. Even `CLI_MITIGATION_VERIFIED` confirms only the selected CLI's session setting, not that PHP core has been patched. See [command output and exit codes](command-reference.md#output-and-exit-codes).

## Can PHP2Shell be automatically fixed by this tool?

No. This preview implements a separate, limited configuration mitigation for CVE-2026-115560. It does not automatically install security releases or certify patch status for the two critical CVEs.

## Can the tool plan a PHP security package upgrade on Ubuntu or Debian?

Yes. Run `php2shell-fix --plan-update --php /usr/bin/php --json` on a supported apt-managed PHP CLI. The result is a read-only inventory and APT simulation, with clear reasons when candidates cannot be verified against upstream fixed release floors. It does not run an upgrade or inspect active web workers.

## What does `--apply` change?

Only a specified PHP CLI-loaded `php.ini`, adding `session.upload_progress.enabled=Off` after creating an integrity-checked backup. This can affect session upload-progress features and is not a substitute for the official core security update.

## Can a failed change be rolled back?

The tool can restore its own `php.ini` change using the printed backup ID, provided the backup is intact and no other process modified the target afterward. It cannot undo package upgrades performed by external tools.

## How do I patch PHP on Windows or Linux?

Use your supported vendor upgrade process and verify serving SAPI, package provenance and extensions. See the [Windows](php2shell-windows.md) and [Linux](php2shell-linux.md) guides.

## Does it support PHP-FPM, Docker or hosting panels?

It only inspects candidate PHP CLI binaries. Docker/managed services require separate vendor remediation. Live PHP-FPM and IIS runtime verification is not implemented.

## Are old PHP versions always vulnerable?

No definitive answer follows from the upstream version string alone: distributions may backport security patches. Confirm the vendor's CVE record and installed package revision.

## Does it send data anywhere?

No. The Go application does not make network requests or submit telemetry. PHP CLI inspection may load locally configured extensions; run only trusted local PHP executables.


## Where are the test results and platform limitations?

Use the [supported-environments matrix](supported-environments.md) and its linked validation records. Each result names the tested runtime, platform, operation and limitations. A compiled binary, detected distribution or successful CLI test does not establish live PHP-FPM, Apache or IIS coverage.

## How should I cite or summarize this project?

Use [CITATION.cff](../CITATION.cff) and include the exact release tag or commit. Link to the relevant [coverage](vulnerability-coverage.md), [platform evidence](supported-environments.md) and [command reference](command-reference.md), keeping their scope limitations with the claim. Cite the PHP project's advisories for vulnerability and patch information rather than treating this repository as the upstream authority.
