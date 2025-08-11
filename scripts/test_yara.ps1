# Simple YARA Test Script
Write-Host "🚨 Testing YARA Detection" -ForegroundColor Red

# Create test files on Desktop
$desktop = [Environment]::GetFolderPath("Desktop")

# Test 1: EICAR file (should trigger)
$eicar = "$desktop\eicar.txt"
$eicarContent = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
Set-Content -Path $eicar -Value $eicarContent -Encoding ASCII
Write-Host "✅ Created EICAR file: $eicar" -ForegroundColor Green

# Test 2: Malware file (should trigger)
$malware = "$desktop\malware.txt"
Set-Content -Path $malware -Value "test malware content" -Encoding UTF8
Write-Host "✅ Created malware file: $malware" -ForegroundColor Green

# Test 3: Crypto file (should trigger)
$crypto = "$desktop\crypto.txt"
Set-Content -Path $crypto -Value "test crypto content" -Encoding UTF8
Write-Host "✅ Created crypto file: $crypto" -ForegroundColor Green

Write-Host ""
Write-Host "🎯 Test files created!" -ForegroundColor Yellow
Write-Host "👀 Watch for Windows notifications in top-right corner" -ForegroundColor Cyan
Write-Host "📱 These files should trigger threat detection" -ForegroundColor Red
Write-Host "⏳ Wait 10 seconds for detection..." -ForegroundColor Yellow

Start-Sleep -Seconds 10

Write-Host ""
Write-Host "🔍 Checking results..." -ForegroundColor Cyan

if (Test-Path $eicar) {
    Write-Host "⚠️  EICAR file still exists" -ForegroundColor Yellow
} else {
    Write-Host "✅ EICAR file processed!" -ForegroundColor Green
}

if (Test-Path $malware) {
    Write-Host "⚠️  Malware file still exists" -ForegroundColor Yellow
} else {
    Write-Host "✅ Malware file processed!" -ForegroundColor Green
}

if (Test-Path $crypto) {
    Write-Host "⚠️  Crypto file still exists" -ForegroundColor Yellow
} else {
    Write-Host "✅ Crypto file processed!" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎯 Test completed! Check agent logs for details." -ForegroundColor Green
Write-Host "📁 Check quarantine folder for quarantined files" -ForegroundColor Blue
