# Equivalent PHP CLI Matrix - November 2, 2026

Ten synthetic cases completed `PASSED_EQUIVALENT_CLI_ONLY`. These are **not physical CentOS 7 or AlmaLinux 9.8 validation**, and do not establish production compatibility. Real upstream PHP binaries ran on Ubuntu 24.04 userspace with the WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`. Only OS identity and package-manager executable presence were represented by fixtures.

| OS identity fixture | Upstream PHP versions | Cases |
| --- | --- | --- |
| CentOS Linux 7 / yum | 7.4.33, 8.0.30, 8.1.34 | 3 |
| AlmaLinux 9.8 / dnf | 7.4.33, 8.0.30, 8.1.34, 8.2.35, 8.3.36, 8.4.27, 8.5.12 | 7 |

The 7.4.33 AlmaLinux fixture covers the upstream version also observed in alt-PHP; the separate discovery regression tests the versioned path. It is not an alt-PHP vendor build. No TuxCare kernel or patchset, licensed cPanel/WHM, CloudLinux patchset, jailed-hosting policy, application or live web worker was reproduced. No production files or credentials were copied into the sandbox, and no project binary was sent to production.

## Method and acceptance

Sources came from the [official PHP release metadata](https://www.php.net/releases/) and distributions, with each archive checked against its published SHA-256. Minimal CLI builds enabled session support and JSON (explicitly enabled for PHP 7.4); CGI and phpdbg were disabled. Builds used two make jobs, with `-g -O2` for 7.4/8.1/8.2 and `-O0 -g0` for 8.3/8.4/8.0/8.5. These are functional tests, not performance comparisons or vendor binary reproduction.

Each test ran in private Linux user, mount and network namespaces. Synthetic writable state used a private tmpfs. An `os-release` fixture was mounted only in the test's namespace; a `yum` or `dnf` presence stub refused execution. This tests platform classification, not a real RPM transaction. Tests supplied an explicit state directory because the existing CLI unnecessarily resolves HOME for read-only commands.

All ten cases returned `scan=0`, `verify_before=2`, `dry_run=0`, `apply=0`, `verify_after=0`, `idempotency=0` with `NO_OP`, `rollback=0`, `verify_restored=2`, and `rpm_plan_refused=3`. The original INI content was restored with SHA-256 `fb9589940b940ce60abb2a8da4421c032440ac4776fd5a4e659ffc2ad594c3c2` in every case. Acceptance rechecked every step, every tested PHP binary hash and every source archive hash.

The tested product binary came from `8a7923b07b658edf355a7aedae28aa43d3f06d74`, with SHA-256 `3d0082b6f86a4cf05ea5bf544e5ab3ebebee75c68140974ac996227f5f6c5cfc`; product code was unchanged through `779e18aced7430635548380d48fccb16c4716fbb`. The consolidated private matrix summary has SHA-256 `2e97bdde166295a66953569a7a8ae34fd409289b51d26b40630b5aa6dfce61ca`.

## Additional regression evidence and review gates

A separate synthetic test set a `user.*` extended attribute on the INI. Apply and rollback succeeded and restored the content hash, but lost the attribute. This confirms that content recovery does not establish complete metadata recovery. Owner/group, ACL and SELinux-label loss remain separate static-review concerns, not independently reproduced by this attribute test.

A synthetic cPanel/alt-PHP layout using real upstream binaries showed that automatic discovery found the default CLI but omitted `/opt/cpanel/ea-php74/root/usr/bin/php` and `/opt/alt/php74/usr/bin/php`. Explicit inspection of both paths correctly reported CLI PHP 7.4.33. This does not validate domain-to-handler mappings. cPanel itself distinguishes [CGI and CLI entry points](https://docs.cpanel.net/ea4/php/easyapache4-and-the-ea-php-cli-package/).

An independent agent reviewed the code and checked both regression artifacts without editing the implementation or repeating the tests. It is not human approval. Mutation promotion remains blocked on three P1 findings: POSIX INI metadata preservation, Windows pre-existing explicit backup-directory ACEs, and trusted state ownership/permissions before rollback. Missing HOME handling and incomplete cPanel discovery are additional P2 findings. The matrix does not close these gates, establish vendor-backport status or authorize production mutation.

## Verified source archives

| PHP tar.xz | SHA-256 |
| --- | --- |
| 7.4.33 | `924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927` |
| 8.0.30 | `216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9` |
| 8.1.34 | `ffa9e0982e82eeaea848f57687b425ed173aa278fe563001310ae2638db5c251` |
| 8.2.35 | `5737b98601fe5ab1b8c5db0c82ed3158acb9283ed3081ffe2faffb9ac81455e6` |
| 8.3.36 | `dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd` |
| 8.4.27 | `dcf93923b0e38e0d5252b25b796520b5a47761a08b3488b6d0b5d1115764d3f0` |
| 8.5.12 | `08bc2eba2a588654ade1357174aa646b761556c862dda0678345ee29ed481209` |
