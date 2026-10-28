# PHP2Shell on Windows

The Windows x64 CLI build can locate PHP on PATH and in selected conventional installation directories, including XAMPP. For an explicit runtime, run `php2shell-fix.exe scan --php C:\path\to\php.exe --json`. Treat each PHP installation separately. Apache/PHP, IIS FastCGI and standalone PHP can use different binaries and INI files.

## Windows Server identification

`scan --json` includes an `iis` report. On Windows, it reads the standard `System32\inetsrv\config\applicationHost.config` and identifies configured PHP FastCGI applications and handler mappings, including location scopes. `CONFIGURED_ONLY` means a path is recorded in the global configuration; the executable, site inheritance, running worker, loaded INI, patch level and service health are unverified. Missing, inaccessible and malformed configurations are reported separately. Delegated `web.config` files and nonstandard IIS configuration paths are outside this detector's scope.

`scan --json` returns a `platform` object. Windows reads `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType` without modification: `ServerNT` means Windows Server, `LanmanNT` means a domain controller, and `WinNT` means a Windows client. Missing or unknown metadata is reported as `windows-unknown`. This operating-system classification remains **DETECTION_ONLY**. Independently, Windows Server 2016, 2019 and 2022 passed limited physical PHP CLI configuration mitigation and rollback tests; see [the validation record](validation/windows-server-2026-10-27.md). Windows Server 2025, IIS and production workers remain unverified.

For IIS/FastCGI, independently verify the actual site's effective FastCGI executable mapping and PHP configuration, worker identity, extension DLLs, PHP architecture and thread-safety build, then establish the loaded PHP version inside the serving process. A separate CLI executable on PATH may be unrelated. Back up vendor-managed runtimes according to their installer or system management procedure, validate a trusted PHP Windows security release, schedule service changes separately, and verify a site-specific response and error logs afterward. The tool does **not** update PHP binaries or restart an application pool.

For CVE-2026-109618/109619, plan a compatible replacement with the latest official PHP Windows security build or a patched trusted distributor package. The PHP team released Windows `-1` rebuilds for 8.2.35/8.3.36/8.4.27/8.5.12 on October 26 to update Brotli. Validate architecture, TS/NTS, extensions, application behavior, server bindings and the loaded runtime; take a vendor-compliant backup first. Do not copy a random DLL or overwrite XAMPP/IIS production binaries with this tool.

For the separate session issue, `--dry-run --php <absolute exe> --ini <absolute ini>` previews assessment; `--apply` appends the official disabled setting only if the PHP CLI loads that exact INI. Restart and validate the *actual* web server separately. No Windows service restart or automated core PHP upgrade is implemented.

Official sources: [PHP security releases](https://www.php.net/) and [Windows builds](https://windows.php.net/download/).
