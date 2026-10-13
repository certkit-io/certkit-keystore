Param(
    [string]$Version = $env:VERSION,
    [string]$InstallDir = "C:\Program Files\CertKit",
    [string]$Owner = "certkit-io",
    [string]$Repo = "certkit-keystore",
    # Github is blocked on many customer networks, so downloads go through the CertKit github proxy
    [string]$GithubProxyBase = "https://app.certkit.io",
    # Use the legacy raw-binary install path instead of the MSI
    [switch]$Binary
)

$ErrorActionPreference = "Stop"

$ServiceName = "certkit-keystore"
$ConfigPath = "C:\ProgramData\CertKit\certkit-keystore\config.json"

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script from an elevated Administrator PowerShell."
    }
}

function Get-LatestReleaseTag {
    $uri = "$GithubProxyBase/github-api-proxy/repos/$Owner/$Repo/releases/latest"
    $latest = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "certkit-keystore-installer" }
    if (-not $latest -or -not $latest.tag_name) {
        throw "Failed to determine latest release tag"
    }
    return $latest.tag_name
}

function Get-VerifiedAsset {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$AssetName,
        [Parameter(Mandatory = $true)][string]$ShaFilePath,
        [Parameter(Mandatory = $true)][string]$TempDir
    )

    $path = Join-Path $TempDir $AssetName
    Write-Host "Downloading $AssetName"
    Invoke-WebRequest -Uri "$BaseUrl/$AssetName" -OutFile $path

    $shaLine = Get-Content $ShaFilePath | Where-Object { $_ -match [regex]::Escape($AssetName) } | Select-Object -First 1
    if (-not $shaLine) {
        throw "Checksum entry not found for $AssetName"
    }
    $expected = ($shaLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $AssetName"
    }
    return $path
}

function Test-MsiProductInstalled {
    # An MSI install registers under a GUID-named uninstall key; script
    # installs never registered one.
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            if ($key.PSChildName -notmatch '^\{[0-9A-Fa-f\-]+\}$') { continue }
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -eq "CertKit Keystore") { return $true }
        }
    }
    return $false
}

function Invoke-LegacyMigration {
    Write-Host "Migrating existing script-based install to the MSI"
    Write-Host "Existing configuration and stored certificates are preserved."

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw "Service '$ServiceName' failed to stop for migration."
    }

    # The MSI must own the service; installing over a pre-existing service it
    # did not create misbehaves, so delete the script-created one first.
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1

    $binDir = Join-Path $InstallDir "bin"
    foreach ($name in @("certkit-keystore.old.exe", "certkit-keystore.new.exe")) {
        $p = Join-Path $binDir $name
        if (Test-Path $p) {
            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Legacy raw-binary install path (-Binary) --------------------------------

function Install-LegacyBinary {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ShaFilePath,
        [Parameter(Mandatory = $true)][string]$TempDir
    )

    $binPath = Get-VerifiedAsset -BaseUrl $BaseUrl -AssetName "certkit-keystore-windows-amd64.exe" -ShaFilePath $ShaFilePath -TempDir $TempDir

    $binDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $installBin = Join-Path $binDir "certkit-keystore.exe"

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $hadExistingService = $null -ne $existingService
    if ($hadExistingService) {
        Write-Host "Stopping existing service '$ServiceName' before upgrade"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
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
        Write-Host "Starting service '$ServiceName'"
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
}

# --- MSI install path (default) ----------------------------------------------

function Install-Msi {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ShaFilePath,
        [Parameter(Mandatory = $true)][string]$TempDir
    )

    $exePath = Get-VerifiedAsset -BaseUrl $BaseUrl -AssetName "certkit-keystore-windows-amd64.exe" -ShaFilePath $ShaFilePath -TempDir $TempDir
    $msiPath = Get-VerifiedAsset -BaseUrl $BaseUrl -AssetName "certkit-keystore-windows-amd64.msi" -ShaFilePath $ShaFilePath -TempDir $TempDir

    # The MSI runs silently, so collect the configuration with the keystore's
    # own interactive prompts first (a no-op when the config is already
    # initialized). The MSI keeps an existing config rather than creating one.
    Write-Host ""
    Write-Host "Running certkit-keystore configuration..."
    Write-Host ""
    & $exePath install --no-service --config $ConfigPath
    if ($LASTEXITCODE -ne 0) {
        throw "certkit-keystore configuration failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path $ConfigPath)) {
        throw "No configuration was saved at $ConfigPath; nothing was installed."
    }

    # A service that exists without an MSI product registration was created by
    # the legacy script (or `certkit-keystore install` by hand); the MSI must
    # not install over it.
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService -and -not (Test-MsiProductInstalled)) {
        Invoke-LegacyMigration
    }

    $logPath = Join-Path $env:TEMP "certkit-keystore-msi-install.log"
    $msiArgs = @(
        "/i", "`"$msiPath`"",
        "/qn", "/norestart",
        "/l*v", "`"$logPath`""
    )
    if ($InstallDir -ne "C:\Program Files\CertKit") {
        $msiArgs += "CERTKITDIR=`"$InstallDir`""
    }

    Write-Host "Installing CertKit Keystore MSI (log: $logPath)"
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -eq 3010) {
        Write-Host "Install succeeded; Windows recommends a reboot to complete (exit code 3010)."
    } elseif ($proc.ExitCode -ne 0) {
        throw "MSI install failed with exit code $($proc.ExitCode). See log: $logPath"
    }

    # The MSI starts the service without waiting; verify it actually runs.
    $deadline = (Get-Date).AddSeconds(20)
    $running = $false
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
            $running = $true
            break
        }
        if ($svc -and $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 2
    }
    if (-not $running) {
        throw "Service '$ServiceName' failed to start. MSI log: $logPath"
    }
}

# --- Main --------------------------------------------------------------------

Assert-Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""
Write-Host "Installing CertKit Keystore..."
Write-Host ""

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestReleaseTag
}

Write-Host "Using release tag: $Version"

$baseUrl = "$GithubProxyBase/github-proxy/$Owner/$Repo/releases/download/$Version"
$tmp = Join-Path $env:TEMP ("certkit-keystore-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $shaPath = Join-Path $tmp "checksums.txt"
    Write-Host "Downloading checksums"
    Invoke-WebRequest -Uri "$baseUrl/checksums.txt" -OutFile $shaPath

    if ($Binary) {
        Install-LegacyBinary -BaseUrl $baseUrl -ShaFilePath $shaPath -TempDir $tmp
    } else {
        Install-Msi -BaseUrl $baseUrl -ShaFilePath $shaPath -TempDir $tmp
    }

    Write-Host ""
    Write-Host "Installation complete."
    Write-Host ""
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
