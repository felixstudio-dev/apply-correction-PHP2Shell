# CentOS Stream 10 Physical CLI Validation - November 2, 2026

An isolated Oracle VirtualBox guest completed `PASSED_CLI_ONLY` at 2026-11-02 16:21:49 UTC, with `Error=null`. This covers a synthetic PHP CLI INI configuration, not PHP-FPM, Apache, production applications, vendor security backports or PHP-core patching. The platform JSON correctly retains `DETECTION_ONLY` for RPM package planning.

The guest ran CentOS Stream 10 x86_64, kernel `6.12.0-279.el10.x86_64`, package `php-cli-8.3.36-1.el10.x86_64`, and SELinux enforcing. Installation used the [official CentOS Stream image](https://mirror.stream.centos.org/10-stream/BaseOS/x86_64/iso/) composition `20261026.0`, with its published SHA-256 verified before boot. The Linux amd64 binary was built from commit `8a7923b07b658edf355a7aedae28aa43d3f06d74` using Go 1.27.3, `CGO_ENABLED=0`, and `vcs.modified=false`.

| Step | Expected and observed exit |
| --- | --- |
| Scan | 0 |
| Verify enabled setting | 2 |
| Dry-run | 0 |
| Apply configuration mitigation | 0 |
| Verify mitigated setting | 0 |
| Repeat apply, reporting `NO_OP` | 0 |
| Rollback | 0 |
| Verify restored setting | 2 |
| Reject unsupported RPM update planning | 3 |

The synthetic INI's original and restored SHA-256 both equal `fb9589940b940ce60abb2a8da4421c032440ac4776fd5a4e659ffc2ad594c3c2`.

The first harness attempt failed at scan with exit 3 and `$HOME is not defined`; no mitigation was applied. The CLI resolves its default state directory even for scan, and the system service environment did not provide a home directory. That attempt's summary, stderr and exception were preserved. The harness was corrected to supply `--state-dir` explicitly for every CLI operation, use journal/console output, report individual steps, enforce a service timeout and omit automatic shutdown. No product source or binary changed between attempts.

During diagnosis after the first attempt, the guest entered a kernel crash-capture environment. The cause remains unconfirmed; this is separate from the recorded scan failure. Serial output and a private memory dump were retained before recovery. The installed filesystem was inspected read-only before the harness correction and the single subsequent test. A stalled live snapshot was canceled and is not counted as a successful backup. The successful CLI test does not establish general guest stability.

| Artifact | SHA-256 |
| --- | --- |
| Official boot ISO | `8cfb13c9b25b1d034a5b2216bc77a638688dd7daba3e511dbd3d5036888c8efe` |
| Tested Linux binary | `3d0082b6f86a4cf05ea5bf544e5ab3ebebee75c68140974ac996227f5f6c5cfc` |
| Successful guest summary | `8eb0d9d6678137a71a99cec6eb4308eba619bc4493ff2e7b4c9838397fba98ea` |

The summary was transferred through the local serial console and its SHA-256 matched the guest's emitted value. Raw logs, the initial failed attempt and the memory dump remain private laboratory evidence; they are not published with this report. No host security settings, credentials, unrelated VMs or production data were changed.
