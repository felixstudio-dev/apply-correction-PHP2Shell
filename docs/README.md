# PHP2Shell Fix documentation

PHP2Shell Fix is an independent Go CLI for local PHP security assessment, read-only Debian/Ubuntu APT update planning and a reversible session upload-progress configuration mitigation. The executable is `php2shell-fix`; the source repository is [felixstudio-dev/apply-correction-PHP2Shell](https://github.com/felixstudio-dev/apply-correction-PHP2Shell).

**Start with the [project README](../README.md#quick-start).** This preview does not install PHP security releases or prove that a web-serving worker is patched. CLI configuration mitigation and PHP core security updates are different actions.

## Find the right guide

| Goal | Guide |
| --- | --- |
| Build and run the tool | [Quick start](../README.md#quick-start) |
| Copy the Linux amd64 CLI into an existing PHP image | [OCI distribution guide](../packaging/README.md) |
| Choose a command, required arguments and output format | [Command reference](command-reference.md) |
| Understand findings and the three CVE scopes | [Vulnerability coverage](vulnerability-coverage.md) |
| Plan a native Debian/Ubuntu PHP package update | [Linux guidance](php2shell-linux.md) |
| Understand Windows PHP CLI and IIS discovery limits | [Windows guidance](php2shell-windows.md) |
| Assess container and image-update boundaries | [Docker guidance](php2shell-docker.md) |
| Check which environments were actually tested | [Supported environments and evidence](supported-environments.md) |
| Restore a tool-created configuration backup | [Backup, recovery and rollback](rollback.md) |
| Understand subprocess, filesystem and trust boundaries | [Architecture](architecture.md) |
| Answer common installation and safety questions | [Frequently asked questions](frequently-asked-questions.md) |

## Read evidence at its stated scope

The [environment matrix](supported-environments.md) links reproducible validation records. Each record describes its tested commit, runtime and limitations. CLI lifecycle tests, operating-system detection and configured IIS bindings are not proof of effective web-worker patching. For a reproducible reference, use a release tag or a commit-specific GitHub permalink instead of assuming that a moving branch has not changed.

For PHP vulnerability details and vendor corrections, follow the primary sources in [vulnerability coverage](vulnerability-coverage.md). This repository documents its own implementation and test evidence; it is not affiliated with or endorsed by the PHP project.

## Get help and contribute

- [GitHub Issues](https://github.com/felixstudio-dev/apply-correction-PHP2Shell/issues): questions and reproducible non-sensitive bugs. Do not publish raw configuration files, credentials, backup data or private host details.
- [Security policy](../SECURITY.md): vulnerability-reporting guidance.
- [Contributing](../CONTRIBUTING.md): change requirements and local checks.
- [Changelog](../CHANGELOG.md): implemented scope.
- [Citation metadata](../CITATION.cff): attribution with the exact version or commit used.
- [MIT license](../LICENSE): license terms.
