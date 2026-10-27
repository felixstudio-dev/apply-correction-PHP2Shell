# PHP2Shell on Windows

The Windows x64 CLI build can locate PHP on PATH and in selected conventional installation directories, including XAMPP. For an explicit runtime, run `php2shell-fix.exe scan --php C:\path\to\php.exe --json`. Treat each PHP installation separately. Apache/PHP, IIS FastCGI and standalone PHP can use different binaries and INI files.

For CVE-2026-109618/109619, plan a compatible replacement with the latest official PHP Windows security build or a patched trusted distributor package. The PHP team released Windows `-1` rebuilds for 8.2.35/8.3.36/8.4.27/8.5.12 on October 26 to update Brotli. Validate architecture, TS/NTS, extensions, application behavior, server bindings and the loaded runtime; take a vendor-compliant backup first. Do not copy a random DLL or overwrite XAMPP/IIS production binaries with this tool.

For the separate session issue, `--dry-run --php <absolute exe> --ini <absolute ini>` previews assessment; `--apply` appends the official disabled setting only if the PHP CLI loads that exact INI. Restart and validate the *actual* web server separately. No Windows service restart or automated core PHP upgrade is implemented.

Official sources: [PHP security releases](https://www.php.net/) and [Windows builds](https://windows.php.net/download/).
