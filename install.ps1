# PowerShell Installation Script for MCP Agent on Windows Server
# Requires Administrator privileges

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

# 2. Copy/Compile Binary
$binaryName = "mcp-agent.exe"
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
