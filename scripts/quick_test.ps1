# Quick YARA Test - Create files that should trigger threat detection
Write-Host "🚨 Quick YARA Threat Detection Test" -ForegroundColor Red

# Create files in Desktop (monitored directory)
$desktop = [Environment]::GetFolderPath("Desktop")

# Test 1: EICAR file (should trigger)
$eicar = "$desktop\eicar_test.txt"
Set-Content -Path $eicar -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' -Encoding ASCII
Write-Host "📁 Created: $eicar" -ForegroundColor Yellow

# Test 2: Malware file (should trigger)
$malware = "$desktop\malware_test.exe"
Set-Content -Path $malware -Value "Simulated malware content" -Encoding UTF8
Write-Host "📁 Created: $malware" -ForegroundColor Yellow

# Test 3: Crypto file (should trigger)
$crypto = "$desktop\crypto_test.py"
Set-Content -Path $crypto -Value "Simulated crypto miner" -Encoding UTF8
Write-Host "📁 Created: $crypto" -ForegroundColor Yellow

Write-Host ""
Write-Host "✅ Test files created!" -ForegroundColor Green
Write-Host "🔍 Watch for Windows notifications in top-right corner" -ForegroundColor Cyan
Write-Host "📱 These files should trigger threat detection and quarantine" -ForegroundColor Red
Write-Host "⏳ Check agent logs for detection details" -ForegroundColor Yellow
