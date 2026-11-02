# Recovery security regression checkpoint — November 2, 2026

This implementation checkpoint addresses three findings from independent agent review: Linux INI metadata loss during replacement, permissive pre-existing Windows backup ACLs, and untrusted rollback state. It also corrects read-only commands requiring HOME and adds versioned cPanel/alt-PHP CLI discovery. No production system was modified.

## Behavior and regression evidence

| Change | Isolated verification |
| --- | --- |
| Linux preserves and verifies UID/GID, permission bits and xattrs before replacement | Apply and rollback with a synthetic named-user POSIX ACL, different UID/GID, and a user xattr; failed CLI validation also restores original content and metadata |
| Unsafe or unsupported metadata fails closed | Special-mode target refused without changing content; external metadata edits refused even when original content has already been restored |
| Existing state is validated without repair | Broad modes, foreign ownership, unsafe writable ancestors, symlink/hardlink recovery records, and modified backup contents refused |
| Windows state created with protected DACL | New directory and explicitly owned private backup tested; explicit foreign read ACE and ancestor delete-child grant refused; inherit-only grants distinguished from applicable ancestor grants |
| Rollback validates recovery files | Broad Windows record/backup DACLs refused before target changes; persistence errors are returned |
| Windows INI DACL retained | Exact DACL comparison before apply, after apply and after rollback |
| Per-target locking supplements state locking | An existing target lock blocks another operation using a different state directory |
| Read-only commands do not resolve a home directory | Scan/report and Linux verify/dry-run passed without HOME; default state resolution remains necessary for mutation unless supplied explicitly |
| Hosting CLI discovery | Versioned EA-PHP/alt-PHP paths discovered in temporary fixtures; explicit selection stays bounded; non-CLI SAPI refused |

Native Windows `go test ./...`, `go vet ./...` and build passed. Linux cross-vet/build passed, followed by the mitigation, inventory and CLI test binaries running in private mount/network namespaces on WSL2 Ubuntu userspace. The ownership/ACL tests used root only inside that disposable filesystem fixture. GitHub Actions results for the final commit are tracked on PR #1; this document does not substitute local results for CI.

The first CI run for `58e5e76` passed Ubuntu but exposed elevated Windows token defaults: files created without an explicit owner could belong to Administrators and were correctly refused by rollback. The follow-up creates every backup, record, lock and replacement temporary with an explicit current-user owner and protected DACL using exclusive creation. Owner validation was not relaxed. Local checks and all ten equivalent cases passed again with that follow-up; elevated CI is tracked on its final commit.

The ten upstream-PHP lifecycle cases were rerun with the corrected binary: CentOS 7 identity fixtures with PHP 7.4.33, 8.0.30 and 8.1.34; AlmaLinux 9.8 identity fixtures with PHP 7.4.33, 8.0.30, 8.1.34, 8.2.35, 8.3.36, 8.4.27 and 8.5.12. All ten are **PASSED_EQUIVALENT_CLI_ONLY**, with expected scan/verify/dry-run/apply/idempotency/rollback exits and original INI content hash restored. The source archives and PHP binaries are the pinned artifacts from [the prior equivalent matrix](php-runtime-equivalents-2026-11-02.md).

The first new matrix harness attempt stopped after scan because both package-manager stubs were present and detection correctly preferred `dnf` over the expected `yum`. Its failed summary was preserved. Correcting the fixture before the subsequent complete run required no product change and no target mutation.

| Local artifact | SHA-256 |
| --- | --- |
| Corrected Linux amd64 executable | `1f2333459eccd55f39a7f2ebc9a990931934928c4bf06e1d865d8d26e0baca7c` |
| Corrected Windows amd64 executable | `ece6a39e5d79a5d1321a704af4ba7f69a9fcd9d0bc6a4e67d47faff591b5d25b` |
| Consolidated ten-case summary | `0a1fe2abeb49e39c94b5fd79bd1a8cda1fce80612c4d98410b8e0af1c2a24329` |

These local binaries were built from the reviewed working tree based on `58e5e76`; their hashes identify those exact test artifacts, not a reproducible clean-commit release build. Raw fixtures, logs and backup contents remain outside the repository.

## Scope and review

The independent agent inspected the final implementation, tests and recovery documentation and reported no remaining P1/P2 findings blocking human review. It did not execute the tests itself or provide human approval.

The matrix is equivalent WSL userspace with OS identity fixtures, not physical CentOS 7/AlmaLinux 9.8, cPanel, TuxCare ELS, vendor-patched PHP or live-site worker validation. Earlier physical Windows Server/CentOS Stream results apply to their recorded older binaries; they were not rerun for this checkpoint. No deployment, PHP package upgrade or production restart occurred.

Windows assurance here is limited to the tested DACL behavior, not complete owner/group/SACL preservation. Linux content-integrity xattrs and unsupported metadata are refused. Existing Linux records without metadata require manual recovery review. Same-user/root hostile writers are outside the trust boundary; coordinate administrative writers and reconcile interrupted locks. See [backup and recovery](../rollback.md) for the full refusal policy.
