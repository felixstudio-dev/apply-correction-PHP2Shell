# Supported Environments and Validation Evidence

Supported statuses are `SUPPORTED`, `PARTIALLY_SUPPORTED`, `DETECTION_ONLY`, `UNTESTED`, and `UNSUPPORTED`. They apply to specific paths rather than entire operating systems.

| Environment | Status (October 27, 2026) | Implemented / tested boundary |
| --- | --- | --- |
| Windows 11 x64, PHP CLI | PARTIALLY_SUPPORTED | Real CLI scan and Windows filesystem mitigation/rollback unit test; production PHP worker upgrade unimplemented |
| Windows 10 | UNTESTED | Windows x64 binaries compile, physical evaluation outstanding |
| Windows Server / IIS FastCGI | UNTESTED | No live IIS worker discovery or post-change health check |
| Linux x64, PHP CLI | PARTIALLY_SUPPORTED (tool execution only) | Native Linux executable and mitigation unit tests passed on Ubuntu 24.04 WSL2; no Linux PHP installation available for live inspection |
| Ubuntu and Debian apt installations | PARTIALLY_SUPPORTED (read-only planning) | APT package inventory, candidate-origin filtering and simulation implemented; planned upgrade execution, backports and active worker proof unimplemented |
| AlmaLinux / Rocky / RHEL dnf installations | DETECTION_ONLY | CLI runtime may be found; backported package evidence not assessed |
| PHP-FPM / Apache / LiteSpeed | DETECTION_ONLY | CLI paths may overlap; serving processes are not verified |
| Docker / Kubernetes | UNSUPPORTED for mutation | Rebuild and redeploy patched base image with owned workflow |
| Plesk / cPanel / hosting platforms | UNSUPPORTED for mutation | Use the hosting vendor's supported update procedure |

This list is intentionally conservative. Passing a Windows or Linux build does not certify a particular hosted PHP runtime. The tool does not elevate privileges, start services, change repositories, deploy updates, or upgrade PHP automatically.
