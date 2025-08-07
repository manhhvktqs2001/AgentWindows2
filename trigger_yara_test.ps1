# Trigger YARA Test - Create file that matches YARA rule
Write-Host "Creating file to trigger YARA rule..." -ForegroundColor Green

# Create directory if not exists
$testDir = "C:\temp\yara_test"
if (!(Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir -Force
    Write-Host "Created test directory: $testDir" -ForegroundColor Yellow
}

# Create file that matches the YARA rule "TestMalware"
$malwareContent = "This is a test malware file for EDR testing"
$malwareFile = "$testDir\test_malware_detection.txt"

Write-Host "Creating malware test file..." -ForegroundColor Yellow
$malwareContent | Out-File -FilePath $malwareFile -Encoding ASCII
Write-Host "Created: $malwareFile" -ForegroundColor Green

# Create file that matches ransomware rule
$ransomwareContent = @"
This file contains encrypt and ransom patterns
encrypt
ransom
bitcoin
payment
"@
$ransomwareFile = "$testDir\test_ransomware.txt"

Write-Host "Creating ransomware test file..." -ForegroundColor Yellow
$ransomwareContent | Out-File -FilePath $ransomwareFile -Encoding ASCII
Write-Host "Created: $ransomwareFile" -ForegroundColor Green

# Create file that matches backdoor rule
$backdoorContent = @"
This file contains backdoor and reverse shell patterns
backdoor
reverse shell
cmd.exe
powershell
"@
$backdoorFile = "$testDir\test_backdoor.txt"

Write-Host "Creating backdoor test file..." -ForegroundColor Yellow
$backdoorContent | Out-File -FilePath $backdoorFile -Encoding ASCII
Write-Host "Created: $backdoorFile" -ForegroundColor Green

# Create executable file with suspicious content
$exeContent = @"
MZ
This is a fake executable with suspicious patterns
This is a test malware file for EDR testing
\x4d\x5a\x90\x00\x03\x00\x00\x00
\x50\x45\x00\x00\x64\x86\x06\x00
"@
$exeFile = "$testDir\suspicious_test.exe"

Write-Host "Creating suspicious exe file..." -ForegroundColor Yellow
$exeContent | Out-File -FilePath $exeFile -Encoding ASCII
Write-Host "Created: $exeFile" -ForegroundColor Green

Write-Host "`nAll test files created!" -ForegroundColor Green
Write-Host "Waiting 15 seconds for agent to detect..." -ForegroundColor Cyan
Start-Sleep -Seconds 15

# Check agent logs for detections
Write-Host "`nChecking agent logs for detections..." -ForegroundColor Yellow
$recentLogs = Get-Content ".\logs\agent.log" -Tail 30
$detectionLogs = $recentLogs | Select-String "detect\|malware\|yara\|threat\|alert\|suspicious\|critical\|high"

if ($detectionLogs) {
    Write-Host "Detections found:" -ForegroundColor Green
    $detectionLogs | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
} else {
    Write-Host "No detections found in recent logs" -ForegroundColor Red
    Write-Host "Checking if files exist..." -ForegroundColor Yellow
    $files = Get-ChildItem $testDir -ErrorAction SilentlyContinue
    if ($files) {
        Write-Host "Files found:" -ForegroundColor Green
        $files | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Yellow }
    } else {
        Write-Host "No test files found" -ForegroundColor Red
    }
}

Write-Host "`nTest completed! Check for Windows notifications." -ForegroundColor Green 