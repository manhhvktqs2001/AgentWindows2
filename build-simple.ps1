# Simple Build Script for EDR Agent Windows
param(
    [string]$Version = "1.0.0",
    [string]$OutputDir = "dist"
)

Write-Host "Building EDR Agent for Windows (without CGO)..." -ForegroundColor Green

# Set environment variables for build without CGO
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir

# Build agent
go build -ldflags "-X main.Version=$Version -X main.BuildTime=$(Get-Date -Format 'yyyy-MM-dd_HH:mm:ss')" -o "$OutputDir/edr-agent.exe" ./main.go

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build completed successfully!" -ForegroundColor Green
    Write-Host "Executable created: $OutputDir/edr-agent.exe" -ForegroundColor Yellow
    
    # Copy configuration files
    Copy-Item "config.yaml" "$OutputDir/" -ErrorAction SilentlyContinue
    
    Write-Host "Files in $OutputDir:" -ForegroundColor Cyan
    Get-ChildItem $OutputDir | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor White
    }
} else {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
} 