# Backup, Recovery and Rollback

Applying the session upload-progress mitigation requires an explicit PHP executable and a matching loaded `php.ini`. The tool backs up the complete existing configuration, calculates its SHA-256, records permission bits, writes a transaction record, checks for out-of-band changes, atomically replaces the selected file, and checks the selected CLI's effective setting.

The default state directory is `~/.php2shell-fix/`. POSIX access is restricted to the owner; Windows uses a restricted user SID ACL and Windows file replacement preserves security attributes. Backup IDs are 32-character lowercase hex values. The backup contains potentially sensitive configuration values; never publish or upload it to issue trackers.

```bash
php2shell-fix --rollback BACKUP_ID
```

The tool validates the backup digest and verifies that the current configuration still matches the exact applied digest. It refuses to overwrite external edits. After rollback, restart the relevant worker using your deployment procedure and verify application health. A rollback of a configuration file does not undo any unrelated PHP installation, extension update, service change, or vendor package upgrade.

If an operation was interrupted, inspect the target `php.ini` and the transaction JSON/backup first. A `.lock` file intentionally prevents another mutation until the previous operation is reconciled. Never delete an active lock or blindly overwrite a newer configuration. If the host crashed after applying the mitigation but before report update, use backup/target hash evidence and manually confirm the appropriate recovery action.
