$ErrorActionPreference = 'Continue'
$backupRoot = Join-Path $env:USERPROFILE 'Documents\Codex\Cloud-D Backups'
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$source = Join-Path $env:USERPROFILE '.cloud-d'
$script = Join-Path $backupRoot 'backup_cloud_d.py'
$log = Join-Path $backupRoot 'backup-runner.log'
$mutex = [System.Threading.Mutex]::new($false, 'Local\CloudD_DailyBackup')

if (-not $mutex.WaitOne(0)) { exit 0 }
try {
    while ($true) {
        $startedAt = Get-Date
        try {
            & $python $script --source $source --destination $backupRoot --retention-days 30 2>&1 |
                ForEach-Object { Add-Content -LiteralPath $log -Value $_ }
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0) {
                $nextRun = $startedAt.AddDays(1)
            } else {
                Add-Content -LiteralPath $log -Value "Backup exited with code $exitCode; retrying in 15 minutes."
                $nextRun = (Get-Date).AddMinutes(15)
            }
        } catch {
            Add-Content -LiteralPath $log -Value "$(Get-Date -Format o) Backup error: $_"
            $nextRun = (Get-Date).AddMinutes(15)
        }
        $sleepSeconds = [Math]::Max(5, [Math]::Ceiling(($nextRun - (Get-Date)).TotalSeconds))
        Start-Sleep -Seconds $sleepSeconds
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
