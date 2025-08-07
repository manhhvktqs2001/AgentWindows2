# Test Rule Loading in Agent
Write-Host "Testing YARA rule loading in agent..." -ForegroundColor Cyan

# Build agent
Write-Host "Building agent..." -ForegroundColor Yellow
go build -o edr-agent.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Build successful!" -ForegroundColor Green

# Create test files with different content
Write-Host "`nCreating test files..." -ForegroundColor Yellow

# Test 1: EICAR content
$eicarContent = "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
$eicarFile = "C:\Users\$env:USERNAME\Desktop\test_eicar.txt"
$eicarContent | Out-File -FilePath $eicarFile -Encoding ASCII

# Test 2: Test malware content
$malwareContent = "This is a test malware file for EDR testing"
$malwareFile = "C:\Users\$env:USERNAME\Desktop\test_malware.txt"
$malwareContent | Out-File -FilePath $malwareFile -Encoding ASCII

# Test 3: Ransomware content
$ransomContent = "encrypt ransom bitcoin payment"
$ransomFile = "C:\Users\$env:USERNAME\Desktop\test_ransomware.txt"
$ransomContent | Out-File -FilePath $ransomFile -Encoding ASCII

# Test 4: Clean content
$cleanContent = "This is a clean file with no threats"
$cleanFile = "C:\Users\$env:USERNAME\Desktop\test_clean.txt"
$cleanContent | Out-File -FilePath $cleanFile -Encoding ASCII

Write-Host "Created test files:" -ForegroundColor Green
Write-Host "  - $eicarFile (EICAR test)" -ForegroundColor Gray
Write-Host "  - $malwareFile (Malware test)" -ForegroundColor Gray
Write-Host "  - $ransomFile (Ransomware test)" -ForegroundColor Gray
Write-Host "  - $cleanFile (Clean test)" -ForegroundColor Gray

# Test each file
Write-Host "`n=== Testing EICAR Detection ===" -ForegroundColor Yellow
& .\edr-agent.exe -test-yara $eicarFile

Write-Host "`n=== Testing Malware Detection ===" -ForegroundColor Yellow
& .\edr-agent.exe -test-yara $malwareFile

Write-Host "`n=== Testing Ransomware Detection ===" -ForegroundColor Yellow
& .\edr-agent.exe -test-yara $ransomFile

Write-Host "`n=== Testing Clean File ===" -ForegroundColor Yellow
& .\edr-agent.exe -test-yara $cleanFile

# Cleanup
Write-Host "`nCleaning up test files..." -ForegroundColor Yellow
Remove-Item $eicarFile -Force -ErrorAction SilentlyContinue
Remove-Item $malwareFile -Force -ErrorAction SilentlyContinue
Remove-Item $ransomFile -Force -ErrorAction SilentlyContinue
Remove-Item $cleanFile -Force -ErrorAction SilentlyContinue

Write-Host "`n✅ Test completed!" -ForegroundColor Green
Write-Host "Check the output above to see if rules are loaded and working correctly." -ForegroundColor Cyan
