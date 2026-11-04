# Installs the independent Windows backup task for Cloud-D.
$ErrorActionPreference = 'Stop'
$backupRoot = Join-Path $env:USERPROFILE 'Documents\Codex\Cloud-D Backups'
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$source = Join-Path $env:USERPROFILE '.cloud-d'
$script = Join-Path $backupRoot 'backup_cloud_d.py'
$runner = Join-Path $backupRoot 'run_cloud_d_backup.cmd'
$loopScript = Join-Path $backupRoot 'Cloud-D-Backup-Loop.ps1'
$taskName = 'Cloud-D Daily Database Backup'
$startupFallbackName = 'Cloud-D Daily Backup.cmd'

New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Python runtime not found at $python. Update the `$python path in this installer to a Python 3.10+ executable."
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'backup_cloud_d.py') -PathType Leaf)) {
    throw "backup_cloud_d.py was not found beside this installer in $PSScriptRoot."
}
if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw "Cloud-D data folder not found at $source. Update `$source in this installer if Cloud-D uses another location."
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Cloud-D-Backup-Loop.ps1') -PathType Leaf)) {
    throw "Cloud-D-Backup-Loop.ps1 was not found beside this installer in $PSScriptRoot."
}

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'backup_cloud_d.py') -Destination $script -Force
$runnerContents = "@echo off`r`n`"$python`" `"$script`" --source `"$source`" --destination `"$backupRoot`" --retention-days 30`r`nexit /b %ERRORLEVEL%"
Set-Content -LiteralPath $runner -Value $runnerContents -Encoding Ascii
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Cloud-D-Backup-Loop.ps1') -Destination $loopScript -Force

try {
    $nextRun = (Get-Date).AddMinutes(2)
    $action = New-ScheduledTaskAction -Execute $runner -WorkingDirectory $backupRoot
    $trigger = New-ScheduledTaskTrigger -Daily -At $nextRun
    $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15) -MultipleInstances IgnoreNew
    $null = Register-ScheduledTask -TaskName $taskName -Description 'Creates a local Cloud-D SQLite and encryption-key backup every 24 hours; keeps 30 days.' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force -ErrorAction Stop
    $registeredTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if (-not $registeredTask) {
        throw "Windows did not register '$taskName'."
    }
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Write-Host "Installed '$taskName'. It runs every 24 hours at $($nextRun.ToString('HH:mm')) local time and catches up after missed runs."
    Write-Host "Check status with: Get-ScheduledTask -TaskName '$taskName' | Get-ScheduledTaskInfo"
} catch {
    $startupDirectory = [Environment]::GetFolderPath('Startup')
    if (-not (Test-Path -LiteralPath $startupDirectory -PathType Container)) {
        throw "Task Scheduler denied registration and the current user's Startup folder is unavailable. $($_.Exception.Message)"
    }
    $startupLauncher = Join-Path $startupDirectory $startupFallbackName
    $powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $launcherContents = "@echo off`r`nstart `"Cloud-D Daily Backup`" /min `"$powerShell`" -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$loopScript`"`r`nexit /b 0"
    Set-Content -LiteralPath $startupLauncher -Value $launcherContents -Encoding Ascii
    $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$loopScript`""
    Start-Process -FilePath $powerShell -ArgumentList $arguments -WindowStyle Hidden -ErrorAction Stop | Out-Null
    $loopMutex = [System.Threading.Mutex]::new($false, 'Local\CloudD_DailyBackup')
    $loopStarted = $false
    try {
        for ($attempt = 0; $attempt -lt 10; $attempt++) {
            if (-not $loopMutex.WaitOne(0)) {
                $loopStarted = $true
                break
            }
            $loopMutex.ReleaseMutex()
            Start-Sleep -Seconds 1
        }
    } finally {
        $loopMutex.Dispose()
    }
    if (-not $loopStarted) {
        throw "The Startup launcher was written, but its background backup loop did not stay running."
    }
    Write-Warning "Task Scheduler registration failed: $($_.Exception.Message)"
    Write-Host "Installed user-level Startup fallback at '$startupLauncher'. It runs every 24 hours while this Windows account is signed in and catches up at the next sign-in."
}
