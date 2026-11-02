# Contributing

Thank you for helping make PHP remediation safer. Open an issue describing the affected platform, expected behavior and reproducible failure before proposing a new privileged remediation adapter.

Changes should preserve read-only defaults, explicit target selection, backup-before-change, redacted errors, dependency hygiene, path safety, idempotency and rollback limits. Include tests that exercise failed and interrupted operations. Run `go test ./...`, `go vet ./...` and appropriate platform builds before opening a pull request.

Do not add exploit payloads, public proof-of-concept RCE code, unsolicited telemetry, shell-downloaded installation scripts or unverified CVE claims. All contributions and public discussions should use English. The MIT license applies to contributions unless explicitly agreed otherwise.
