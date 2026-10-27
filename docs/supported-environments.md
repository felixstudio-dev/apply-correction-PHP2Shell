# Supported Environments and Validation Evidence

Supported statuses are `SUPPORTED`, `PARTIALLY_SUPPORTED`, `DETECTION_ONLY`, `UNTESTED`, and `UNSUPPORTED`. They apply to specific paths rather than entire operating systems.

| Environment | Status (October 27, 2026) | Implemented / tested boundary |
| --- | --- | --- |
| Windows 11 x64, PHP CLI | PARTIALLY_SUPPORTED | Real CLI scan and Windows filesystem mitigation/rollback unit test; production PHP worker upgrade unimplemented |
| Windows 10 / Windows 11 clients | DETECTION_ONLY for platform classification; Windows 10 runtime UNTESTED | Windows registry `ProductType=WinNT` identifies client installations; CLI scan is separate from worker verification |
| Windows Server (including IIS / FastCGI) | DETECTION_ONLY; physical server remediation UNTESTED | `ProductType=ServerNT` distinguishes Windows Server; standard global IIS FastCGI application registrations and handler mappings are read as configuration evidence, while effective site, application pool, worker and patch validation remain unverified |
| Windows Server domain controllers | DETECTION_ONLY | `ProductType=LanmanNT` is reported distinctly; operational remediation requires separate administrative change control |
| Linux x64, PHP CLI | PARTIALLY_SUPPORTED (tool execution only) | Native Linux executable and mitigation unit tests passed on Ubuntu 24.04 WSL2; no Linux PHP installation available for live inspection |
| Ubuntu and Debian apt installations | PARTIALLY_SUPPORTED (read-only planning) | APT package inventory, candidate-origin filtering and simulation implemented; planned upgrade execution, backports and active worker proof unimplemented |
| AlmaLinux / Rocky / RHEL dnf installations | DETECTION_ONLY | CLI runtime may be found; backported package evidence not assessed |
| CentOS Linux / CentOS Stream / Oracle Linux / Amazon Linux / CloudLinux | DETECTION_ONLY | RPM family and available `dnf` or `yum` are identified; no automated RPM upgrade plan, vendor-backport proof or real-server validation |
| Fedora / openSUSE / SLES / Arch / Alpine / Gentoo / NixOS / Void / Slackware / Clear Linux | DETECTION_ONLY | Distribution family and known package-manager executable are described when discoverable; vendor updates remain manual |
| Other or unidentified Linux distributions | DETECTION_ONLY | Generic PHP CLI scan is attempted; unknown vendor packaging is left unclassified |
| PHP-FPM / Apache / LiteSpeed | DETECTION_ONLY | CLI paths may overlap; serving processes are not verified |
| Docker / Kubernetes | UNSUPPORTED for mutation | Rebuild and redeploy patched base image with owned workflow |
| Plesk / cPanel / hosting platforms | UNSUPPORTED for mutation | Use the hosting vendor's supported update procedure |

Every JSON assessment includes a `platform` object with `distribution`, `family`, `package_manager`, `update_planning`, `status` and limitations. Windows reports an additional `iis` configuration-discovery section whose mappings remain `CONFIGURED_ONLY`. On Windows, classification reads the operating system's registry `ProductType` (Windows Server, domain controller, client, or unknown). On Linux it reads `/etc/os-release`; unknown distributions remain identifiable as generic Linux without pretending to have a safe vendor upgrade recipe. `--plan-update` is currently available **only for specifically verified native Debian/Ubuntu APT installations**.

This list is intentionally conservative. These are detection paths, not a claim that every Linux distribution, Windows version or Windows Server edition has undergone physical remediation testing. Passing a Windows or Linux build does not certify a hosted PHP runtime. The tool does not elevate privileges, start services, change repositories, deploy updates, or upgrade PHP automatically.
