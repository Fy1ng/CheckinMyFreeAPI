[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$OutputDir = '',
    [ValidateSet('windows-amd64', 'linux-amd64', 'linux-arm64', 'linux-desktop-amd64', 'linux-desktop-arm64')]
    [string[]]$Targets = @('windows-amd64', 'linux-amd64', 'linux-arm64')
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw 'Go 1.26.10 or later is required to build this application.'
}
if ([string]::IsNullOrWhiteSpace($Version)) {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $description = & git -C $repoRoot describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0) { $Version = [string]$description }
    }
    if ([string]::IsNullOrWhiteSpace($Version)) { $Version = 'dev' }
}
if ($Version -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$') {
    throw 'Version must contain 1..128 ASCII letters, numbers, dots, underscores, pluses or hyphens.'
}
if ([string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir = Join-Path $repoRoot 'dist/go' }
$OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
[System.IO.Directory]::CreateDirectory($OutputDir) | Out-Null
$originalEnvironment = @{}
foreach ($name in @('CGO_ENABLED', 'GOOS', 'GOARCH')) {
    $originalEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
}
$artifacts = [System.Collections.Generic.List[string]]::new()
Push-Location $repoRoot
try {
    $hostOS = [string](& go env GOHOSTOS)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the Go host operating system.' }
    $hostArch = [string](& go env GOHOSTARCH)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read the Go host architecture.' }
    $selectedTargets = @($Targets | Select-Object -Unique)
    $linuxDesktopTargets = @($selectedTargets | Where-Object { $_ -like 'linux-desktop-*' })
    foreach ($desktopTarget in $linuxDesktopTargets) {
        if ($hostOS -ne 'linux' -or $desktopTarget -ne "linux-desktop-$hostArch") {
            throw "Linux desktop target $desktopTarget requires a matching native Linux host with GTK 3 and WebKitGTK 4.1 development libraries."
        }
        & pkg-config --exists gtk+-3.0 webkit2gtk-4.1 gdk-3.0 x11
        if ($LASTEXITCODE -ne 0) { throw 'Linux desktop builds need pkg-config, GTK 3, WebKitGTK 4.1 and X11 development libraries.' }
    }
    $env:CGO_ENABLED = '0'
    $env:GOOS = $hostOS
    $env:GOARCH = $hostArch
    $licenseArguments = @('--out', (Join-Path $OutputDir 'GO_DEPENDENCY_LICENSES.txt'))
    if ($selectedTargets -contains 'windows-amd64') { $licenseArguments += '--desktop' }
    if ($linuxDesktopTargets.Count -gt 0) { $licenseArguments += '--linux-desktop' }
    & go run -mod=readonly ./scripts/license-notices @licenseArguments
    if ($LASTEXITCODE -ne 0) { throw 'Go dependency license collection failed.' }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $OutputDir 'LICENSE')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination (Join-Path $OutputDir 'THIRD_PARTY_NOTICES.md')
    Copy-Item -LiteralPath (Join-Path $repoRoot 'docs/go-edition.md') -Destination (Join-Path $OutputDir 'README.md')
    foreach ($target in $selectedTargets) {
        $parts = $target.Split('-')
        $env:GOOS = $parts[0]
        $env:GOARCH = $parts[-1]
        $env:CGO_ENABLED = '0'
        $targetDir = Join-Path $OutputDir $target
        [System.IO.Directory]::CreateDirectory($targetDir) | Out-Null
        $baseFlags = "-s -w -X=main.version=$Version"
        if ($env:GOOS -eq 'windows') {
            Write-Output "Building $target/checkin.exe (Wails desktop)"
            & go build -mod=readonly -p 1 -tags 'desktop,production' -trimpath -buildvcs=false -ldflags "$baseFlags -H=windowsgui" -o (Join-Path $targetDir 'checkin.exe') ./cmd/checkin
            if ($LASTEXITCODE -ne 0) { throw "Go build failed for $target/checkin.exe." }
            $artifacts.Add("$target/checkin.exe")
            Write-Output "Building $target/checkin-cli.exe (console)"
            & go build -mod=readonly -p 1 -tags nogui -trimpath -buildvcs=false -ldflags $baseFlags -o (Join-Path $targetDir 'checkin-cli.exe') ./cmd/checkin
            if ($LASTEXITCODE -ne 0) { throw "Go build failed for $target/checkin-cli.exe." }
            $artifacts.Add("$target/checkin-cli.exe")
        } elseif ($target -like 'linux-desktop-*') {
            $env:CGO_ENABLED = '1'
            Write-Output "Building $target/checkin (Wails GTK desktop)"
            & go build -mod=readonly -p 1 -tags 'desktop,production,gtk3' -trimpath -buildvcs=false -ldflags $baseFlags -o (Join-Path $targetDir 'checkin') ./cmd/checkin
            if ($LASTEXITCODE -ne 0) { throw "Go build failed for $target/checkin." }
            $artifacts.Add("$target/checkin")
        } else {
            Write-Output "Building $target/checkin"
            & go build -mod=readonly -p 1 -tags nogui -trimpath -buildvcs=false -ldflags $baseFlags -o (Join-Path $targetDir 'checkin') ./cmd/checkin
            if ($LASTEXITCODE -ne 0) { throw "Go build failed for $target/checkin." }
            $artifacts.Add("$target/checkin")
        }
    }
    $lines = foreach ($relativePath in ($artifacts | Sort-Object)) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $OutputDir $relativePath) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relativePath"
    }
    $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $OutputDir 'SHA256SUMS'), (($lines -join "`n") + "`n"), $utf8WithoutBom)
    Write-Output "Built CheckinMyFreeAPI $Version. SHA256SUMS contains this run's $($artifacts.Count) binaries."
    Write-Output "Output: $OutputDir"
} finally {
    Pop-Location
    foreach ($name in $originalEnvironment.Keys) {
        [System.Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
}
