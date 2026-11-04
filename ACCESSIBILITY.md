# Accessibility

PHP2Shell Fix helps people inspect PHP CLI installations and understand configuration changes that can affect their systems. People with disabilities should be able to read the documentation, understand command output, report problems and contribute to the project. Clear warnings and recovery instructions matter especially when a command can change a file.

This statement covers the command-line interface, repository documentation and contribution process. The project is an early preview. We have not completed an accessibility evaluation and do not claim verified accessibility conformance.

## Priorities

We aim to make common tasks usable with a keyboard and understandable when terminal output is read aloud, enlarged, copied or reviewed as a text file. Our priorities are to:

- Keep commands, help, results and errors available as text, without requiring a mouse, color or an image to understand them.
- Explain what a command does, which configuration it affects and how to interpret its result. Make the difference between inspection, preview, application and rollback clear.
- Keep output in a predictable reading order and avoid unnecessary decoration or dense formatting that makes speech output harder to follow.
- Provide descriptive headings, meaningful links and text explanations for documentation images.
- Use plain English and explain specialist terms. Current contributor guidance asks for contributions and public discussions in English; translated interfaces and documentation have not been evaluated.

These are design priorities, not a claim that every task or assistive-technology combination has been tested.

## Contributor expectations

Follow [CONTRIBUTING.md](CONTRIBUTING.md). For changes to commands, output or documentation:

- Keep essential information in text. Do not communicate success, failure or risk through color, symbols or screenshots alone.
- Preserve a useful reading order in help and reports. Explain errors and the next safe step without requiring users to inspect an image.
- Use descriptive Markdown headings and links. Add useful alternative text for informative images and include command examples as selectable text.
- Check the affected task using keyboard input and review the output as plain text. Consider narrow terminal windows and long paths when changing formatting.
- Describe the task checked, environment, observed result and remaining limitations in the pull request. If you test with a screen reader or another assistive technology, name its version and the terminal or browser used. Do not describe untested combinations as supported.
- Add focused regression coverage when a code change fixes a reproducible output or interaction problem. Use synthetic examples and remove private paths, host details and credentials from evidence.

The repository CI runs Go tests, static analysis and builds on Ubuntu and Windows. These checks do not establish accessibility. There is currently no dedicated automated accessibility check or documented assistive-technology test matrix.

## Reporting accessibility issues

[Open an accessibility issue](https://github.com/felixstudio-dev/apply-correction-PHP2Shell/issues/new) with a title such as “Accessibility: cannot follow scan output.” You can also add a comment to an existing issue about the same barrier. A short text description is enough to start.

Helpful details, when available, include:

- The task you were trying to complete and the command or documentation URL involved.
- What happened, what you expected and whether you could continue another way.
- The project version or commit, operating system and terminal or browser version.
- Any assistive technology or input method relevant to reproducing the problem, if you choose to share it.

Screenshots and recordings are optional. You do not need to disclose a disability, medical information or personal circumstances. If GitHub itself prevents you from filing an issue, someone you trust may report on your behalf; maintainers can work from a description of the barrier.

Public issues are visible to others. Remove credentials, host inventories, private paths and configuration contents. For security-sensitive details, follow [SECURITY.md](SECURITY.md) rather than posting them publicly.

### Severity

Reporters do not need to assign severity. Maintainers can describe impact during triage using these guidelines; they are not existing issue labels or response-time guarantees:

- **Blocking:** a person cannot complete an essential task and has no practical workaround, such as being unable to understand which file an apply command will change.
- **Significant:** a task is possible only with substantial extra effort or assistance, such as output whose reading order makes results difficult to associate with installations.
- **Minor:** a task remains possible but causes avoidable confusion or effort, such as an unclear documentation link.

Impact on safe use, available workarounds and the affected task guide prioritization. A security or data-loss risk also needs assessment under the security policy.

### How we respond

Maintainers review reports as capacity allows. There is no guaranteed acknowledgement or resolution deadline. The issue thread is the place to record questions, reproduction findings, status and any known workaround.

When a fix is available, maintainers should link the relevant change and identify the version or commit that includes it. Reporters are welcome, but not required, to check whether the fix resolves their task. If a barrier cannot be addressed promptly, the issue should explain the limitation and any safe alternative that is known.

## Ownership and maintenance

The repository maintainers are responsible for triaging accessibility reports, reviewing changes for barriers and keeping this statement consistent with the project. Accessibility review is part of reviewing changes to user-facing commands and documentation.

Maintainers should revisit this statement when preparing a release, when the interface or supported environments change, and when new testing evidence becomes available. This is the expected review cadence, not a claim that past releases received an accessibility audit. When responsibility changes, the incoming maintainers should take over open accessibility issues and this document's review.

## Supported environments

PHP2Shell Fix is a command-line tool for Windows and Linux. Platform-specific functional evidence and limitations are listed in [supported environments](docs/supported-environments.md). Functional CLI tests and successful builds do not prove accessibility in a particular terminal or assistive technology.

Keyboard command entry, text output and JSON reports are the primary ways to interact with the tool. The `--json` and `--report` options can help users process results with their preferred tools; those reports may contain sensitive environment details and should be stored privately.

No specific screen reader, braille display, speech-input tool, terminal magnification setup or browser combination currently has documented accessibility validation. Documentation is available as Markdown in the repository; its rendered navigation also depends on the GitHub interface and the user's browser.

## Known limitations

We have not documented a systematic assistive-technology evaluation. Users may encounter barriers that have not yet been reported, particularly when navigating long reports, technical status names or lengthy filesystem paths. These are areas needing evaluation, not confirmed defects in every environment.

Saving text output for review or using JSON with a preferred reader may offer an alternative to following a long terminal session. This does not replace clear human-readable output. There are no accessibility issue links recorded in this statement yet; that does not establish an absence of barriers. Please report problems using the process above.

## Feedback and improvements

Suggestions for this statement, clearer examples or better testing practices are welcome through [repository issues](https://github.com/felixstudio-dev/apply-correction-PHP2Shell/issues) or a pull request following [the contributor guidance](CONTRIBUTING.md). Describe the task an improvement would help with and any evidence you can share safely. Report an active barrier through the accessibility reporting process above so its impact can be tracked.
