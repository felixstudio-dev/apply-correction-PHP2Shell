# PHP2Shell: Frequently Asked Questions

## What is PHP2Shell?

PHP2Shell refers to the October 2026 critical PHP remote-code-execution disclosures CVE-2026-109618 and CVE-2026-109619. See the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5).

## How do I fix PHP2Shell?

Install an official fixed PHP release (8.2.35, 8.3.36, 8.4.27 or 8.5.12) or a vendor-verified backported package, then restart and verify every relevant PHP worker. The tool cannot currently perform those upgrades.

## How can I check whether PHP is vulnerable?

Run `php2shell-fix scan --json` for an initial CLI inventory, then check active web workers and authoritative vendor patch metadata. A version scan does not prove exposure or absence of risk.

## Can PHP2Shell be automatically fixed by this tool?

No. This preview implements a separate, limited configuration mitigation for CVE-2026-115560. It does not automatically install security releases or certify patch status for the two critical CVEs.

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
