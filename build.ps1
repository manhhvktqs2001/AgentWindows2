# Build Windows Agent
param(
    [string]$Version = "1.0.0",
    [string]$OutputDir = "dist"
)

Write-Host "Building EDR Agent for Windows..." -ForegroundColor Green

# Set environment variables
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "1"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir

# Build agent
go build -ldflags "-X main.Version=$Version -X main.BuildTime=$(Get-Date -Format 'yyyy-MM-dd_HH:mm:ss')" -o "$OutputDir/edr-agent.exe" ./main.go

# Copy configuration files
Copy-Item "config.yaml" "$OutputDir/" -ErrorAction SilentlyContinue

# Create installer package
Write-Host "Creating installer package..." -ForegroundColor Yellow

# Create installation script
$installScript = @"
# EDR Agent Windows Installer
param(
    [string]`$InstallPath = "C:\Program Files\EDR-Agent",
    [string]`$ServiceName = "EDR-Agent",
    [switch]`$Uninstall
)

if (`$Uninstall) {
    Write-Host "Uninstalling EDR Agent..." -ForegroundColor Yellow
    
    # Stop service
    Stop-Service -Name `$ServiceName -ErrorAction SilentlyContinue
    
    # Remove service
    sc.exe delete `$ServiceName
    
    # Remove files
    Remove-Item -Path `$InstallPath -Recurse -Force -ErrorAction SilentlyContinue
    
    Write-Host "EDR Agent uninstalled successfully" -ForegroundColor Green
    exit 0
}

Write-Host "Installing EDR Agent..." -ForegroundColor Green

# Create installation directory
New-Item -ItemType Directory -Force -Path `$InstallPath

# Copy files
Copy-Item "edr-agent.exe" -Destination `$InstallPath
Copy-Item "config.yaml" -Destination "`$InstallPath\config.yaml"

# Generate agent ID
`$AgentID = [System.Guid]::NewGuid().ToString()
(Get-Content "`$InstallPath\config.yaml") -replace 'id: ""', "id: ``"`$AgentID``"" | Set-Content "`$InstallPath\config.yaml"

# Install service
`$ServicePath = "`$InstallPath\edr-agent.exe"
sc.exe create `$ServiceName binPath= `$ServicePath start= auto DisplayName= "EDR Agent Service"

# Set service description
sc.exe description `$ServiceName "Endpoint Detection and Response Agent"

# Start service
Start-Service -Name `$ServiceName

# Add firewall rule
New-NetFirewallRule -DisplayName "EDR Agent" -Direction Outbound -Port 5000 -Protocol TCP -Action Allow

Write-Host "EDR Agent installed and started successfully" -ForegroundColor Green
Write-Host "Agent ID: `$AgentID" -ForegroundColor Cyan
"@

$installScript | Out-File -FilePath "$OutputDir/install.ps1" -Encoding UTF8

Write-Host "Build completed: $OutputDir" -ForegroundColor Green
Write-Host "Files created:" -ForegroundColor Yellow
Write-Host "  - edr-agent.exe" -ForegroundColor White
Write-Host "  - config.yaml" -ForegroundColor White
Write-Host "  - install.ps1" -ForegroundColor White
Write-Host ""
Write-Host "To install, run: .\install.ps1" -ForegroundColor Cyan
Write-Host "To uninstall, run: .\install.ps1 -Uninstall" -ForegroundColor Cyan 