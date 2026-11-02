# Windows Server Physical CLI Validation - October 27 to November 2, 2026

This record describes four reproducible, isolated Oracle VirtualBox 7.2.2 guest tests. The tested operation is the PHP CLI `session.upload_progress.enabled` INI mitigation and recovery. It does **not** patch the PHP executable or prove remediation of PHP-core CVEs, including CVE-2026-109618 and CVE-2026-109619. No IIS, FastCGI, Apache worker, site health check or production rollout was tested.

| Guest | PHP build | Result | UTC completion time |
| --- | --- | --- | --- |
| Windows Server 2016 Standard Evaluation, build 14393 | PHP 8.5.12 CLI, NTS, Visual C++ 2022 x64 | `PASSED_CLI_ONLY` | 2026-10-27 22:06:39 |
| Windows Server 2019 Standard Evaluation, build 17763 | PHP 8.5.12 CLI, NTS, Visual C++ 2022 x64 | `PASSED_CLI_ONLY` | 2026-10-28 00:06:20 |
| Windows Server 2022 Standard Evaluation, build 20348 | PHP 8.5.12 CLI, NTS, Visual C++ 2022 x64 | `PASSED_CLI_ONLY` | 2026-10-27 22:09:25 |
| Windows Server 2025 Standard Evaluation, build 26100 | PHP 8.5.12 CLI, NTS, Visual C++ 2022 x64 | `PASSED_CLI_ONLY` | 2026-11-02 14:53:49 |

For the 2016, 2019 and 2022 guests, the host executor exited `0`. The 2025 guest ran the same guest QA script directly in the operator-authenticated console, without guestcontrol authentication. For all four guests, guest step exit codes were `vc_runtime_install_if_needed=0`, `scan=0`, `verify_before=2`, `dry_run=0`, `apply=0`, `verify_after=0`, `idempotency=0`, `rollback=0` and `verify_restored=2`. Exit `2` on verification was expected when the mitigation was absent; exit `0` after applying the configuration mitigation confirmed its CLI state, and exit `2` after rollback confirmed restoration. The host verified the SHA-256 of the payload inputs before execution; the test also recorded integrity-checked recovery. All four machine-readable guest summaries reported `Error=null`.

The test binary SHA-256 was `F47CAE5895040A1F9B39F75C822DC1C2AA765E664BAD348EFA8061647ADC2D71`. The PHP ZIP SHA-256 was `2A36A2EDCB7A5B9252F638FD5E4CF84D7F6E066092654220DC0B63E5CF4E9723`. The raw `summary.json` reports were retained in the private, temporary laboratory results folders for the 2016, 2019, 2022 and 2025 guests; this public record omits workstation paths, credentials and environment-specific details.

Windows Server 2025 Standard Evaluation build 26100 completed at 2026-11-02 14:53:49 UTC with PHP 8.5.12 CLI NTS, Visual C++ 2022 x64. Its summary reported `PASSED_CLI_ONLY` and `Error=null`. The payload was transferred using a local read-only data ISO; the original guest summary was retrieved through Guest Additions properties and verified byte-for-byte by SHA-256 (`049EAA8B5E01BD4DA5932AE8D09F9A8482531BF2EA4DBF1FA51B4D2014670BA1`). This validates the guest CLI lifecycle, not the password-based host transport. The broader Windows Server platform and IIS/FastCGI remain detection-only outside the explicit CLI path above. Neither PHP version alone nor a successful mitigation is evidence that a given CVE was patched in a serving process.
