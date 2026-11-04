# Cloud-D local backups

`backup_cloud_d.py` makes a consistent SQLite snapshot of both Cloud-D databases and includes the active 32-byte encryption key. Each dated backup has a SHA-256 manifest; database snapshots are checked with SQLite `quick_check`. The key and databases must be restored together.

On this Windows PC, the backup destination is `%USERPROFILE%\Documents\Codex\Cloud-D Backups`. Backups retain 30 days. Access is limited by the current user's Documents folder permissions. Authentication tokens and staff registration codes are intentionally excluded.

## Daily Windows task

The preferred task is **Cloud-D Daily Database Backup**, scheduled every 24 hours starting two minutes after installation, with `StartWhenAvailable` behavior and retries. If Windows denies task registration, the installer uses the current user's Startup folder to launch `Cloud-D-Backup-Loop.ps1` in the background. That fallback runs every 24 hours and catches up at the next sign-in, but only while the Windows account is signed in. Both methods run while Codex is closed.

These backups cover only the databases and encryption key in this Windows user's `%USERPROFILE%\.cloud-d` folder. They do not back up the hosted Render service; its current free instance uses temporary storage.

Run `Install-Cloud-D-Backup-Task.ps1` once in Windows PowerShell. It copies no application data and prefers a scheduled task; if Windows denies that, it installs the user-level Startup fallback and reports which method was set up. Verify the scheduled task with:

```powershell
Get-ScheduledTask -TaskName 'Cloud-D Daily Database Backup' | Get-ScheduledTaskInfo
```

A successful run reports `LastTaskResult` as `0`. Keep the PC powered on for the scheduled time; `StartWhenAvailable` catches up when Windows comes back online.

## Restore

Stop Cloud-D first. Restore `cloud-d.sqlite3`, `cloud-d-backup.sqlite3`, and `encryption.key` together into the active data folder, then start Cloud-D. Never replace the key independently; encrypted file contents cannot be read with a different key.
