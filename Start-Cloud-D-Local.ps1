$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$dataDirectory = Join-Path $env:USERPROFILE '.cloud-d'
$staffCodePath = Join-Path $dataDirectory 'staff-registration-code'
$stdoutPath = Join-Path $dataDirectory 'server.log'
$stderrPath = Join-Path $dataDirectory 'server-error.log'

if (-not (Test-Path -LiteralPath $python)) {
    throw "Cloud-D Python runtime was not found at $python"
}

New-Item -ItemType Directory -Path $dataDirectory -Force | Out-Null
if (Test-Path -LiteralPath $staffCodePath) {
    $staffCode = (Get-Content -LiteralPath $staffCodePath -Raw).Trim()
    if ($staffCode.Length -ge 16) {
        $env:CLOUD_D_STAFF_REGISTRATION_CODE = $staffCode
    }
}

$listener = Get-NetTCPConnection -LocalPort 8765 -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @('127.0.0.1', '::1') -and $_.OwningProcess -gt 0 } |
    Select-Object -First 1

if (-not $listener) {
    Start-Process -FilePath $python `
        -ArgumentList '-m cloud_d.main --host 127.0.0.1 --port 8765 --no-browser' `
        -WorkingDirectory $projectRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
}
