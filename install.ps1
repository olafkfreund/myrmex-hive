# PowerShell Installation Script for MCP Agent on Windows Server
# Requires Administrator privileges
#
# By default this script downloads a pre-built "myrmex-agent.exe" binary from
# the project's GitHub Releases (GoReleaser output), so target/edge nodes do
# not need a Go toolchain installed. Pass -BuildFromSource to fall back to the
# old behaviour of compiling locally (or using an existing .\bin\agent.exe),
# which is useful for airgapped environments or local development builds.
param(
    [switch]$BuildFromSource
)

# GitHub repository that publishes GoReleaser release archives/binaries.
$githubRepo = "olafkfreund/myrmex-hive"
$githubApiLatestRelease = "https://api.github.com/repos/$githubRepo/releases/latest"

# Self-elevate check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Please run this PowerShell script as Administrator!"
    Exit
}

Write-Host "=== Windows MCP Agent Installer ===" -ForegroundColor Cyan

# Define installation paths
$installDir = "C:\Program Files\mcp-agent"
$configDir = "C:\ProgramData\mcp-agent"

# 1. Create Directories
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

# 2. Obtain Binary: download a pre-built release by default, or compile from
#    source when -BuildFromSource is passed.
$binaryName = "mcp-agent.exe"

function Get-ReleaseBinary {
    # Downloads and verifies the GoReleaser release archive for this arch,
    # extracts it, and installs myrmex-agent.exe to "$installDir\$binaryName".
    # Returns $true on success, $false on any failure (caller decides how to
    # respond, e.g. suggest -BuildFromSource).

    # Normalize the OS architecture to Go's GOARCH naming used by GoReleaser.
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { $goArch = "amd64" }
        "ARM64" { $goArch = "arm64" }
        default {
            Write-Warning "Unsupported architecture '$($env:PROCESSOR_ARCHITECTURE)'."
            return $false
        }
    }

    Write-Host "Querying GitHub API for the latest release ($githubRepo)..."
    try {
        $release = Invoke-RestMethod -Uri $githubApiLatestRelease -UseBasicParsing
    } catch {
        Write-Warning "Failed to query $githubApiLatestRelease : $_"
        return $false
    }

    # GoReleaser names Windows archives "<project>_<version>_windows_<arch>.zip".
    $assetSuffix = "windows_${goArch}.zip"
    $asset = $release.assets | Where-Object { $_.name -like "*$assetSuffix" } | Select-Object -First 1
    if (-not $asset) {
        Write-Warning "Could not find a release asset for windows/$goArch."
        return $false
    }

    $checksumAsset = $release.assets | Where-Object { $_.name -eq "checksums.txt" } | Select-Object -First 1

    $tmpDir = Join-Path $env:TEMP ("myrmex-install-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
    $archivePath = Join-Path $tmpDir $asset.name

    try {
        Write-Host "Downloading $($asset.name) ..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -UseBasicParsing

        if ($checksumAsset) {
            Write-Host "Downloading checksums.txt for verification..."
            $checksumPath = Join-Path $tmpDir "checksums.txt"
            try {
                Invoke-WebRequest -Uri $checksumAsset.browser_download_url -OutFile $checksumPath -UseBasicParsing
                $checksumLine = Select-String -Path $checksumPath -Pattern ([regex]::Escape($asset.name)) | Select-Object -First 1
                if ($checksumLine) {
                    $expectedHash = ($checksumLine.Line -split '\s+')[0].ToUpperInvariant()
                    Write-Host "Verifying checksum..."
                    $actualHash = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToUpperInvariant()
                    if ($actualHash -ne $expectedHash) {
                        Write-Warning "Checksum verification failed for $($asset.name) (expected $expectedHash, got $actualHash)."
                        return $false
                    }
                } else {
                    Write-Warning "Checksum entry for $($asset.name) not found in checksums.txt; skipping verification."
                }
            } catch {
                Write-Warning "Could not download checksums.txt; skipping verification: $_"
            }
        } else {
            Write-Warning "No checksums.txt published with this release; skipping verification."
        }

        Write-Host "Extracting archive..."
        $extractDir = Join-Path $tmpDir "extracted"
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        $agentExe = Get-ChildItem -Path $extractDir -Filter "myrmex-agent.exe" -Recurse | Select-Object -First 1
        if (-not $agentExe) {
            Write-Warning "myrmex-agent.exe not found inside downloaded archive."
            return $false
        }

        Copy-Item $agentExe.FullName "$installDir\$binaryName" -Force
        return $true
    } catch {
        Write-Warning "Failed to download/install release binary: $_"
        return $false
    } finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($BuildFromSource) {
    Write-Host "-BuildFromSource specified: using local compile path."
    if (Test-Path ".\bin\agent.exe") {
        Write-Host "Found compiled agent.exe. Copying to installation directory..."
        Copy-Item ".\bin\agent.exe" "$installDir\$binaryName" -Force
    } elseif (Get-Command "go" -ErrorAction SilentlyContinue) {
        Write-Host "Compiling agent binary locally..."
        go build -o "$installDir\$binaryName" cmd/agent/main.go
    } else {
        Write-Warning "Go compiler not found and no pre-built binary at .\bin\agent.exe. Please compile it first or place the executable."
        Exit
    }
} else {
    Write-Host "Downloading pre-built agent binary from GitHub Releases..."
    if (-not (Get-ReleaseBinary)) {
        Write-Warning "Failed to download the release binary."
        Write-Warning "Re-run with -BuildFromSource to compile locally instead (requires the Go toolchain)."
        Exit
    }
}

Write-Host "Binary installed to $installDir\$binaryName" -ForegroundColor Green

# 3. Setup Configuration
$configPath = "$configDir\config.json"
$privateKeyPath = "$configDir\id_ed25519"
# Convert backslashes to forward slashes for JSON path compatibility
$jsonKeyPath = $privateKeyPath.Replace("\", "/")

if (-not (Test-Path $configPath)) {
    Write-Host "Generating default agent configuration..."
    $agentID = $env:COMPUTERNAME
    $gatewayAddr = Read-Host "Enter Gateway Address [localhost:2222]"
    if ([string]::IsNullOrEmpty($gatewayAddr)) { $gatewayAddr = "localhost:2222" }

    $configJson = @"
{
  "agent_id": "$agentID",
  "gateway_addr": "$gatewayAddr",
  "private_key_path": "$jsonKeyPath",
  "allowed_commands": [
    {"name": "ipconfig", "args_regex": ".*"},
    {"name": "ping", "args_regex": ".*"},
    {"name": "systeminfo", "args_regex": ".*"}
  ]
}
"@
    Set-Content -Path $configPath -Value $configJson
    Write-Host "Configuration created at $configPath" -ForegroundColor Green
}

# 4. Generate SSH Keys
$sshKeygenPath = "ssh-keygen"
if (-not (Get-Command "ssh-keygen" -ErrorAction SilentlyContinue)) {
    # Check default OpenSSH location on Windows Server
    $fallbackSshKeygen = "C:\Windows\System32\OpenSSH\ssh-keygen.exe"
    if (Test-Path $fallbackSshKeygen) {
        $sshKeygenPath = $fallbackSshKeygen
    } else {
        Write-Warning "ssh-keygen utility not found. Please install OpenSSH feature or place keys manually."
    }
}

if (-not (Test-Path $privateKeyPath)) {
    Write-Host "Generating secure Ed25519 authentication keys..."
    & $sshKeygenPath -t ed25519 -N '""' -f $privateKeyPath
    Write-Host "Authentication keypair generated." -ForegroundColor Green
}

# 5. Create Background Startup Task
Write-Host "Registering background scheduled task to run at startup..."
$taskName = "MCP-Agent"

# Unregister if already exists
Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

$action = New-ScheduledTaskAction -Execute "$installDir\$binaryName" -Argument "-config `"$configPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

$task = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal

# Start the task now
Start-ScheduledTask -TaskName $taskName

Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "MCP Agent installation completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "The agent is running in the background as a Scheduled Task ('$taskName')."
Write-Host "Register the public key below in your Gateway settings:" -ForegroundColor Yellow
if (Test-Path "$privateKeyPath.pub") {
    Get-Content "$privateKeyPath.pub"
} else {
    Write-Warning "Public key file not found. Ensure it was generated at $privateKeyPath.pub"
}
Write-Host "===========================================" -ForegroundColor Cyan
