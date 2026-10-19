# Run manually when the local WebUI must load updated backend code.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TestRoot,
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateRange(1024, 65535)][int]$Port = 18765,
    [switch]$UseSystemChrome,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$testDirectory = (Resolve-Path -LiteralPath $TestRoot).Path
$repositoryDirectory = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$python = Join-Path $repositoryDirectory '.venv\Scripts\python.exe'
$passwordFile = Join-Path $testDirectory 'web-password'
$keyFile = Join-Path $testDirectory 'keys\master.key'
$pidFile = Join-Path $testDirectory 'process-id'
foreach ($required in @($python, $passwordFile, $keyFile, $pidFile)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw 'A required local test file is missing.' }
}
$origin = "http://127.0.0.1:$Port"
$password = (Get-Content -LiteralPath $passwordFile -Raw).Trim()
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$null = Invoke-RestMethod -Uri "$origin/api/login" -Method Post -Headers @{Origin = $origin} `
    -ContentType 'application/json' -Body (@{password = $password} | ConvertTo-Json) -WebSession $session
$status = Invoke-RestMethod -Uri "$origin/api/status" -WebSession $session
if ($status.running) { throw 'A task is running. Wait for it to finish before updating the WebUI.' }
$beforeRestart = Invoke-RestMethod -Uri "$origin/api/config" -WebSession $session
if ($beforeRestart.config.schedule.enabled) {
    throw 'Pause scheduled tasks in the WebUI before using this local update helper.'
}
$listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen)
if ($listeners.Count -ne 1) { throw 'Unexpected listener count. No process was stopped.' }
$serverProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($listeners[0].OwningProcess)"
$recordedId = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
if ($serverProcess.ProcessId -ne $recordedId -and $serverProcess.ParentProcessId -ne $recordedId) {
    throw 'The listener does not match the recorded local test process. No process was stopped.'
}
$launcherProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$recordedId"
if ($serverProcess.CommandLine -notmatch '\s-m\s+server\s*$' -or
    -not $launcherProcess.CommandLine -or
    $launcherProcess.CommandLine.IndexOf($python, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
    throw 'The listener is not the expected repository WebUI. No process was stopped.'
}
$cache = Join-Path $testDirectory 'data\auth-cache\auth-state.enc'
$cacheHash = if (Test-Path -LiteralPath $cache) { (Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash } else { $null }
if ($CheckOnly) {
    Write-Output 'Local test service is idle and ownership checks passed. No changes made.'
    return
}

Stop-Process -Id $serverProcess.ProcessId
Wait-Process -Id $serverProcess.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
$env:CHECKIN_WEB_HOST = '127.0.0.1'
$env:CHECKIN_WEB_PORT = [string]$Port
$env:CHECKIN_WEB_DATA_DIR = Join-Path $testDirectory 'data'
$env:CHECKIN_WEB_KEY_FILE = $keyFile
$env:CHECKIN_WEB_PASSWORD_FILE = $passwordFile
$env:CHECKIN_AUTH_ROOT = Join-Path $testDirectory 'data\auth-live'
$env:CLOAKBROWSER_AUTO_UPDATE = 'false'
$bundledBrowser = Join-Path $testDirectory 'browser-cache\chromium-146.0.7680.177.5\chrome.exe'
if (Test-Path -LiteralPath $bundledBrowser) { $env:CLOAKBROWSER_BINARY_PATH = $bundledBrowser }
$launcher = Start-Process -FilePath $python -ArgumentList '-m', 'server' -WorkingDirectory $repositoryDirectory `
    -WindowStyle Hidden -RedirectStandardOutput (Join-Path $testDirectory 'stdout.log') `
    -RedirectStandardError (Join-Path $testDirectory 'stderr.log') -PassThru
Set-Content -LiteralPath $pidFile -Value $launcher.Id
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    try {
        $null = Invoke-RestMethod -Uri "$origin/healthz" -TimeoutSec 2
        $ready = $true
        break
    } catch { Start-Sleep -Milliseconds 200 }
}
if (-not $ready) { throw 'The updated WebUI did not become ready. Check stderr.log in the local test directory.' }
if ($UseSystemChrome) {
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-RestMethod -Uri "$origin/api/login" -Method Post -Headers @{Origin = $origin} `
        -ContentType 'application/json' -Body (@{password = $password} | ConvertTo-Json) -WebSession $session
    $current = Invoke-RestMethod -Uri "$origin/api/config" -WebSession $session
    $previousEngine = $current.config.browser.engine
    $before = $current.config | ConvertTo-Json -Depth 40 -Compress
    $current.config.browser.engine = 'chrome'
    $saved = Invoke-RestMethod -Uri "$origin/api/config" -Method Put `
        -Headers @{Origin = $origin; 'X-CSRF-Token' = $login.csrf} -ContentType 'application/json' `
        -Body (@{config = $current.config; revision = $current.revision} | ConvertTo-Json -Depth 40 -Compress) -WebSession $session
    $saved.config.browser.engine = $previousEngine
    if (($saved.config | ConvertTo-Json -Depth 40 -Compress) -ne $before) {
        throw 'Unexpected configuration difference. Review the saved configuration before running a task.'
    }
}
if ($cacheHash -and (Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash -ne $cacheHash) {
    throw 'The previous browser snapshot changed. Review it before running a task.'
}
Write-Output "Updated local WebUI: $origin"
if ($UseSystemChrome) { Write-Output 'System Chrome is selected. Existing browser state was preserved.' }
Write-Output 'Refresh the WebUI and log in again. No identity login or check-in task was started.'
