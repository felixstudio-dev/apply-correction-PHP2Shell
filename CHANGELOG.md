# Changelog

## Unreleased — October 27, 2026

- Added Go-based bounded PHP CLI discovery and JSON security assessment.
- Added upstream patch-floor comparisons for CVE-2026-109618 and CVE-2026-109619, with conservative vendor-backport handling.
- Added conditional CVE-2026-115560 configuration mitigation with a protected backup, explicit target binding, CLI re-check and integrity-checked rollback.
- Added a conservative read-only Debian/Ubuntu APT upgrade planner: installed package inventory, official repository host checks, upstream fixed-release floors and dependency-change simulation.
- Added unit tests, cross-platform CI, security guidance, public documentation and citation metadata.
- Explicitly excluded unattended PHP upgrades, worker restarts and unsupported platform claims.
