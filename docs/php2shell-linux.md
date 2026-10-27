# PHP2Shell on Linux

Run `php2shell-fix scan --json` to inventory discoverable CLI binaries. Linux package-managed PHP may reside in multiple branch-specific paths, and a web server's PHP-FPM pool may load another configuration.

For CVE-2026-109618/109619, inspect **vendor** advisories and installed package changelogs before planning an update. Debian/Ubuntu security packages, RHEL-compatible vendor packages and third-party PHP repositories can contain backported fixes without changing the upstream PHP version string. Use the existing trusted `apt`/`dnf`/vendor update path after checking dependency compatibility, backups and service health. The tool currently produces guidance only and does not invoke any package manager.

For CVE-2026-115560, the PHP project's temporary recommendation is `session.upload_progress.enabled=0`. The CLI can safely modify only the explicitly selected loaded INI. PHP-FPM commonly uses `/etc/php/<version>/fpm/php.ini`, separate from the CLI INI; the CLI check does not prove FPM behavior. Confirm server configuration provenance and perform an owned service restart and health check. Do not use an application-level `ini_set` as the mitigation for early request processing.

References: [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5), [Red Hat CVE guidance](https://access.redhat.com/security/cve/cve-2026-109619).
