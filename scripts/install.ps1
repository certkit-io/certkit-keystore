Param(
    [string]$Version = $env:VERSION,
    [string]$InstallDir = "C:\Program Files\CertKit",
    [string]$Owner = "certkit-io",
    [string]$Repo = "certkit-keystore"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script from an elevated Administrator PowerShell."
    }
}

function Get-LatestReleaseTag {
    $uri = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $latest = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "certkit-keystore-installer" }
    if (-not $latest -or -not $latest.tag_name) {
        throw "Failed to determine latest release tag"
    }
    return $latest.tag_name
}

Assert-Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""
Write-Host "Installing CertKit Keystore..."
Write-Host ""

$binName = "certkit-keystore"
$assetBin = "${binName}-windows-amd64.exe"
$assetSha = "checksums.txt"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestReleaseTag
}

Write-Host "Using release tag: $Version"

$baseUrl = "https://github.com/$Owner/$Repo/releases/download/$Version"
$tmp = Join-Path $env:TEMP ("certkit-keystore-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $binPath = Join-Path $tmp $assetBin
    $shaPath = Join-Path $tmp $assetSha

    Write-Host "Downloading $assetBin"
    Invoke-WebRequest -Uri "$baseUrl/$assetBin" -OutFile $binPath

    Write-Host "Downloading checksums"
    Invoke-WebRequest -Uri "$baseUrl/$assetSha" -OutFile $shaPath

    Write-Host "Verifying checksum"
    $shaLine = Get-Content $shaPath | Where-Object { $_ -match [regex]::Escape($assetBin) } | Select-Object -First 1
    if (-not $shaLine) {
        throw "Checksum entry not found for $assetBin"
    }
    $expected = ($shaLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $binPath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $assetBin"
    }

    $binDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $installBin = Join-Path $binDir "certkit-keystore.exe"

    $existingService = Get-Service -Name $binName -ErrorAction SilentlyContinue
    $hadExistingService = $null -ne $existingService
    if ($hadExistingService) {
        Write-Host "Stopping existing service '$binName' before upgrade"
        Stop-Service -Name $binName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    if (Test-Path $installBin) {
        Write-Host "Updating binary at $installBin"
    } else {
        Write-Host "Installing binary to $installBin"
    }
    Copy-Item -Force -Path $binPath -Destination $installBin

    Write-Host ""
    Write-Host "Running certkit-keystore install..."
    Write-Host ""
    & $installBin install

    if ($hadExistingService) {
        Write-Host "Starting service '$binName'"
        Start-Service -Name $binName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }

    Write-Host ""
    Write-Host "Installation complete."
    Write-Host ""
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
