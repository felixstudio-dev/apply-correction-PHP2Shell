# Security Policy

## Supported status

This project is an early preview and has no security-supported stable release. Its `--apply` mode is confined to the explicitly selected session upload-progress configuration mitigation; it does not patch PHP core binaries.

## Reporting vulnerabilities

Please report tool vulnerabilities privately using the repository's GitHub **Security > Report a vulnerability** feature when enabled, or contact the repository owner privately through verified official maintainer contact channels. Do not post exploit details, credentials, backups, logs or private server configuration in public issues.

Include affected commit, operating system, exact command (with secrets removed), impact, and a non-destructive reproduction where feasible. Coordinated disclosure is preferred.

## Operational safety

Execute only trusted releases/source commits. Review the plan before running any privileged command. Protect generated reports and saved php.ini backups. The tool does not provide a vulnerability exploitation test, signed binary attestation, vendor package authenticity verdict, PHP worker restart, or guaranteed rollback of third-party package upgrades.
