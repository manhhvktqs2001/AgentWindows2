# Comprehensive YARA Threat Detection Test
Write-Host "🧪 Testing YARA Threat Detection..." -ForegroundColor Cyan

# Create test directory on Desktop
$desktop = [Environment]::GetFolderPath("Desktop")
$testDir = "$desktop\YARA_TEST"

if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force | Out-Null
    Write-Host "✅ Created test directory: $testDir" -ForegroundColor Green
}

# Test file 1: EICAR test file (should trigger threat detection)
$eicarPath = "$testDir\eicar_test.txt"
$eicarContent = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
Set-Content -Path $eicarPath -Value $eicarContent -Encoding ASCII
Write-Host "📝 Created EICAR test file: $eicarPath" -ForegroundColor Cyan

# Test file 2: Malware test file (should trigger threat detection)
$malwarePath = "$testDir\malware_test.exe"
$malwareContent = "This is a simulated malware file for testing YARA rules. Contains suspicious patterns that should trigger detection."
Set-Content -Path $malwarePath -Value $malwareContent -Encoding UTF8
Write-Host "📝 Created malware test file: $malwarePath" -ForegroundColor Cyan

# Test file 3: Crypto test file (should trigger threat detection)
$cryptoPath = "$testDir\crypto_miner.py"
$cryptoContent = "This is a simulated crypto miner file for testing YARA rules. Contains suspicious patterns that should trigger detection."
Set-Content -Path $cryptoPath -Value $cryptoContent -Encoding UTF8
Write-Host "📝 Created crypto test file: $cryptoPath" -ForegroundColor Cyan

# Test file 4: Normal file (should NOT trigger threat detection)
$normalPath = "$testDir\normal_file.txt"
$normalContent = "This is a normal file that should not trigger any YARA rules. Just regular text content."
Set-Content -Path $normalPath -Value $normalContent -Encoding UTF8
Write-Host "📝 Created normal file: $normalPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "🎯 Test files created successfully!" -ForegroundColor Green
Write-Host "📋 Expected behavior:" -ForegroundColor Yellow
Write-Host "  - EICAR malware and crypto files should trigger threat detection" -ForegroundColor Red
Write-Host "  - Normal file should NOT trigger any alerts" -ForegroundColor Green
Write-Host "  - Windows notifications should appear for threats" -ForegroundColor Cyan
Write-Host "  - Files should be quarantined and uploaded to MinIO" -ForegroundColor Blue
Write-Host ""

Write-Host "⏳ Waiting 10 seconds for file monitoring to detect changes..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "🔍 Checking if files were processed..." -ForegroundColor Cyan

# Check EICAR file
if (Test-Path $eicarPath) {
    Write-Host "⚠️  EICAR file still exists - may not have been detected" -ForegroundColor Yellow
} else {
    Write-Host "✅ EICAR file was processed (likely quarantined)" -ForegroundColor Green
}

# Check malware file
if (Test-Path $malwarePath) {
    Write-Host "⚠️  Malware file still exists - may not have been detected" -ForegroundColor Yellow
} else {
    Write-Host "✅ Malware file was processed (likely quarantined)" -ForegroundColor Green
}

# Check crypto file
if (Test-Path $cryptoPath) {
    Write-Host "⚠️  Crypto file still exists - may not have been detected" -ForegroundColor Yellow
} else {
    Write-Host "✅ Crypto file was processed (likely quarantined)" -ForegroundColor Green
}

# Check normal file
if (Test-Path $normalPath) {
    Write-Host "✅ Normal file still exists (correctly not detected)" -ForegroundColor Green
} else {
    Write-Host "⚠️  Normal file was processed (unexpected)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎯 Test completed! Check the agent logs for detection details." -ForegroundColor Green
Write-Host "🔔 Look for Windows notifications in the top-right corner" -ForegroundColor Cyan
Write-Host "📁 Check quarantine folder for quarantined files" -ForegroundColor Blue
