# EDR Agent Windows Installer
param(
    [string]$InstallPath = "C:\Program Files\EDR-Agent",
    [string]$ServiceName = "EDR-Agent",
    [switch]$Uninstall
)

if ($Uninstall) {
    Write-Host "Uninstalling EDR Agent..." -ForegroundColor Yellow
    
    # Stop service
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    # Remove service
    sc.exe delete $ServiceName
    
    # Remove files
    Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "EDR Agent uninstalled successfully" -ForegroundColor Green
    exit 0
}

Write-Host "Installing EDR Agent..." -ForegroundColor Green

# Create installation directory
New-Item -ItemType Directory -Force -Path $InstallPath

# Copy files
Copy-Item "edr-agent.exe" -Destination $InstallPath
Copy-Item "config.yaml" -Destination "$InstallPath\config.yaml"

# Generate agent ID
$AgentID = [System.Guid]::NewGuid().ToString()
(Get-Content "$InstallPath\config.yaml") -replace 'id: ""', "id: `"$AgentID`"" | Set-Content "$InstallPath\config.yaml"

# Install service
$ServicePath = "$InstallPath\edr-agent.exe"
sc.exe create $ServiceName binPath= $ServicePath start= auto DisplayName= "EDR Agent Service"

# Set service description
sc.exe description $ServiceName "Endpoint Detection and Response Agent"

# Start service
Start-Service -Name $ServiceName

# Add firewall rule
New-NetFirewallRule -DisplayName "EDR Agent" -Direction Outbound -Port 5000 -Protocol TCP -Action Allow

Write-Host "EDR Agent installed and started successfully" -ForegroundColor Green
Write-Host "Agent ID: $AgentID" -ForegroundColor Cyan
