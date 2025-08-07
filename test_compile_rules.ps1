# Test YARA Rules Compilation
Write-Host "=== Testing YARA Rules Compilation ===" -ForegroundColor Cyan

# Build agent
Write-Host "Building agent..." -ForegroundColor Yellow
go build -o edr-agent.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build successful!" -ForegroundColor Green

# Check rules directory
Write-Host "`nChecking YARA rules directory..." -ForegroundColor Yellow
$rulesPath = "yara-rules"
if (Test-Path $rulesPath) {
    $ruleFiles = Get-ChildItem -Path $rulesPath -Recurse -Filter "*.yar" | Measure-Object
    Write-Host "Found $($ruleFiles.Count) .yar files in $rulesPath" -ForegroundColor Green
} else {
    Write-Host "❌ Rules directory not found: $rulesPath" -ForegroundColor Red
    exit 1
}

# Create test EICAR file
Write-Host "`nCreating test EICAR file..." -ForegroundColor Yellow
$eicarContent = "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
$eicarFile = "C:\Users\$env:USERNAME\Desktop\test_eicar_compile.txt"
$eicarContent | Out-File -FilePath $eicarFile -Encoding ASCII

Write-Host "Created EICAR test file: $eicarFile" -ForegroundColor Green

# Test with debug logging
Write-Host "`n=== Testing Rules Compilation and Scanning ===" -ForegroundColor Yellow
$env:LOG_LEVEL = "debug"
$output = & .\edr-agent.exe -test-yara $eicarFile 2>&1

# Filter and display relevant output
Write-Host "`n=== YARA Rules Loading Output ===" -ForegroundColor Cyan
$output | Select-String -Pattern "YARA|rule|Rule|loaded|Loaded|error|Error|compile|Compile" | ForEach-Object {
    Write-Host $_.Line -ForegroundColor Gray
}

Write-Host "`n=== Scan Results ===" -ForegroundColor Cyan
$output | Select-String -Pattern "THREAT|Match|match|EICAR|eicar" | ForEach-Object {
    Write-Host $_.Line -ForegroundColor Yellow
}

# Cleanup
Write-Host "`nCleaning up..." -ForegroundColor Yellow
Remove-Item $eicarFile -Force -ErrorAction SilentlyContinue

Write-Host "`n✅ Compilation test completed!" -ForegroundColor Green
