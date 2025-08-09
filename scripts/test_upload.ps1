# Simple test script for quarantine upload functionality
Write-Host "🧪 Testing Quarantine Upload" -ForegroundColor Green

# Test server connectivity
$serverUrl = "http://192.168.20.85:5000"
Write-Host "🔗 Testing server connectivity to: $serverUrl" -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "$serverUrl/api/v1/health" -Method GET -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Server is reachable" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Server responded with status: $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ Server is not reachable: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "💡 Make sure the EDR server is running on $serverUrl" -ForegroundColor Cyan
    exit 1
}

# Test MinIO connectivity
Write-Host "🔗 Testing MinIO connectivity..." -ForegroundColor Yellow
try {
    $minioResponse = Invoke-WebRequest -Uri "http://localhost:9000" -Method GET -TimeoutSec 5
    if ($minioResponse.StatusCode -eq 200) {
        Write-Host "✅ MinIO is reachable" -ForegroundColor Green
    } else {
        Write-Host "⚠️  MinIO responded with status: $($minioResponse.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ MinIO is not reachable: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "💡 Make sure MinIO is running on localhost:9000" -ForegroundColor Cyan
}

Write-Host "`n🎯 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Start the EDR server: cd Server && go run cmd/server/main.go" -ForegroundColor White
Write-Host "2. Start the EDR agent: cd Agent/AgentWindows && go run main.go" -ForegroundColor White
Write-Host "3. Test with real malware files" -ForegroundColor White
