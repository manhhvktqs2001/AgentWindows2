# EDR Agent Windows Installation Script
# Run as Administrator

param(
    [string]$ServerURL = "http://192.168.20.85:5000",
    [string]$AgentName = "",
    [switch]$Force
)

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "=== EDR Agent Windows Installation ===" -ForegroundColor Green
Write-Host "Server URL: $ServerURL" -ForegroundColor Yellow
Write-Host "Agent Name: $AgentName" -ForegroundColor Yellow

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentDir = Split-Path -Parent $ScriptDir
$AgentExe = Join-Path $AgentDir "edr-agent.exe"

# Check if agent executable exists
if (-not (Test-Path $AgentExe)) {
    Write-Error "Agent executable not found: $AgentExe"
    Write-Host "Please run this script from the agent directory" -ForegroundColor Red
    exit 1
}

# Generate agent name if not provided
if (-not $AgentName) {
    $AgentName = $env:COMPUTERNAME + "-agent"
}

Write-Host "Installing EDR Agent as Windows Service..." -ForegroundColor Green

# Stop existing service if running
$ServiceName = "EDR-Agent"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Install service
try {
    & $AgentExe -install
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Service installed successfully" -ForegroundColor Green
    } else {
        throw "Service installation failed"
    }
} catch {
    Write-Error "Failed to install service: $_"
    exit 1
}

# Update configuration
$ConfigPath = Join-Path $AgentDir "config.yaml"
if (Test-Path $ConfigPath) {
    Write-Host "Updating configuration..." -ForegroundColor Yellow
    
    # Read current config
    $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Yaml
    
    # Update server URL
    $Config.server.url = $ServerURL
    
    # Update agent name
    $Config.agent.name = $AgentName
    
    # Enable monitoring
    $Config.monitoring.file_system.enabled = $true
    $Config.monitoring.processes.enabled = $true
    $Config.monitoring.network.enabled = $true
    $Config.monitoring.registry.enabled = $true
    $Config.yara.enabled = $true
    
    # Save updated config
    $Config | ConvertTo-Yaml | Set-Content $ConfigPath
    
    Write-Host "✅ Configuration updated" -ForegroundColor Green
}

# Start service
Write-Host "Starting EDR Agent service..." -ForegroundColor Yellow
try {
    Start-Service -Name $ServiceName
    Write-Host "✅ Service started successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to start service: $_"
    exit 1
}

# Check service status
Start-Sleep -Seconds 3
$Service = Get-Service -Name $ServiceName
if ($Service.Status -eq "Running") {
    Write-Host "✅ EDR Agent is running" -ForegroundColor Green
} else {
    Write-Host "⚠️  Service status: $($Service.Status)" -ForegroundColor Yellow
}

# Display service information
Write-Host "`n=== Installation Complete ===" -ForegroundColor Green
Write-Host "Service Name: $ServiceName" -ForegroundColor White
Write-Host "Agent Name: $AgentName" -ForegroundColor White
Write-Host "Server URL: $ServerURL" -ForegroundColor White
Write-Host "`nUseful Commands:" -ForegroundColor Cyan
Write-Host "  - Check status: Get-Service $ServiceName" -ForegroundColor Gray
Write-Host "  - Stop service: Stop-Service $ServiceName" -ForegroundColor Gray
Write-Host "  - Start service: Start-Service $ServiceName" -ForegroundColor Gray
Write-Host "  - View logs: Get-EventLog -LogName Application -Source $ServiceName" -ForegroundColor Gray

Write-Host "`nInstallation completed successfully!" -ForegroundColor Green 