package response

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// WindowsToastNotifier hiển thị thông báo góc phải màn hình
type WindowsToastNotifier struct {
	config    *config.ResponseConfig
	logger    *utils.Logger
	scriptDir string
}

// NewWindowsToastNotifier tạo Windows toast notifier mới
func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsToastNotifier {
	return &WindowsToastNotifier{
		config:    cfg,
		logger:    logger,
		scriptDir: "notifications",
	}
}

// Start khởi tạo Windows toast notifier
func (wtn *WindowsToastNotifier) Start() error {
	wtn.logger.Info("Starting Windows Corner Notification System...")

	// Tạo thư mục notifications
	err := os.MkdirAll(wtn.scriptDir, 0755)
	if err != nil {
		wtn.logger.Warn("Failed to create notification scripts directory: %v", err)
	}

	// Tạo HTML notification script (đáng tin cậy hơn PowerShell Forms)
	err = wtn.createHTMLNotificationScript()
	if err != nil {
		wtn.logger.Warn("Failed to create HTML notification script: %v", err)
	}

	// Tạo PowerShell script backup
	err = wtn.createSimplePowerShellScript()
	if err != nil {
		wtn.logger.Warn("Failed to create PowerShell backup script: %v", err)
	}

	wtn.logger.Info("Corner notification system started successfully")
	return nil
}

// Stop dừng Windows toast notifier
func (wtn *WindowsToastNotifier) Stop() {
	wtn.logger.Info("Corner notification system stopped")
}

// SendNotification hiển thị thông báo ở góc phải màn hình
func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	wtn.logger.Info("Showing corner notification: %s", content.Title)

	// In ra console trước
	fmt.Printf("\n🚨🚨🚨 SECURITY ALERT 🚨🚨🚨\n")
	fmt.Printf("Title: %s\n", content.Title)
	fmt.Printf("Message: %s\n", content.Message)
	fmt.Printf("Severity: %s\n", wtn.getSeverityText(content.Severity))
	fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")

	// Debug: Kiểm tra thư mục notifications
	wtn.logger.Info("Checking notifications directory: %s", wtn.scriptDir)
	if _, err := os.Stat(wtn.scriptDir); os.IsNotExist(err) {
		wtn.logger.Warn("Notifications directory does not exist, creating...")
		err = os.MkdirAll(wtn.scriptDir, 0755)
		if err != nil {
			wtn.logger.Error("Failed to create notifications directory: %v", err)
		}
	}

	// Thử YARA Alert HTML notification trước (style như hình)
	wtn.logger.Info("Attempting YARA alert notification...")
	err := wtn.showYARAAlertNotification(content)
	if err == nil {
		wtn.logger.Info("✅ YARA alert notification displayed successfully")
		return nil
	}
	wtn.logger.Error("❌ YARA alert notification failed: %v", err)

	// Fallback: HTML notification thường
	wtn.logger.Info("Attempting HTML notification...")
	err = wtn.showHTMLNotification(content)
	if err == nil {
		wtn.logger.Info("✅ HTML notification displayed successfully")
		return nil
	}
	wtn.logger.Error("❌ HTML notification failed: %v", err)

	// Fallback: PowerShell notification đơn giản
	wtn.logger.Info("Attempting PowerShell notification...")
	err = wtn.showSimplePowerShellNotification(content)
	if err == nil {
		wtn.logger.Info("✅ PowerShell notification displayed successfully")
		return nil
	}
	wtn.logger.Error("❌ PowerShell notification failed: %v", err)

	// Final fallback: msg command
	wtn.logger.Info("Attempting msg command notification...")
	err = wtn.showMsgNotification(content)
	if err != nil {
		wtn.logger.Error("❌ All notification methods failed: %v", err)
		// Thử phương thức đơn giản nhất - MessageBox
		return wtn.showSimpleMessageBox(content)
	}
	wtn.logger.Info("✅ Msg command notification displayed successfully")
	return nil
}

// showYARAAlertNotification hiển thị notification kiểu YARA Alert như trong hình
func (wtn *WindowsToastNotifier) showYARAAlertNotification(content *NotificationContent) error {
	// Tạo file HTML notification kiểu YARA Alert
	htmlFile := filepath.Join(wtn.scriptDir, "yara_alert.hta")

	title := strings.ReplaceAll(content.Title, `"`, `&quot;`)
	message := strings.ReplaceAll(content.Message, `"`, `&quot;`)
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	severityText := wtn.getSeverityText(content.Severity)
	bgColor := wtn.getHTMLBackgroundColor(content.Severity)
	textColor := wtn.getHTMLTextColor(content.Severity)

	// Lấy thông tin YARA rule từ content
	ruleName := "Unknown Rule"
	if content.ThreatInfo != nil && content.ThreatInfo.ThreatName != "" {
		ruleName = content.ThreatInfo.ThreatName
	}

	riskScore := "40/100" // Default risk score
	if content.Severity >= 4 {
		riskScore = "80/100"
	} else if content.Severity >= 3 {
		riskScore = "60/100"
	} else if content.Severity >= 2 {
		riskScore = "40/100"
	} else {
		riskScore = "20/100"
	}

	details := "YARA rule detection triggered"
	if content.ThreatInfo != nil && content.ThreatInfo.Description != "" {
		details = content.ThreatInfo.Description
	}

	htmlContent := fmt.Sprintf(`
<html>
<head>
    <title>EDR Security Alert</title>
    <HTA:APPLICATION 
        ID="EDRAlert"
        APPLICATIONNAME="EDR Security Alert"
        BORDER="thin"
        BORDERSTYLE="normal"
        CAPTION="no"
        MAXIMIZEBUTTON="no"
        MINIMIZEBUTTON="no"
        SYSMENU="no"
        SCROLL="no"
        WINDOWSTATE="normal">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 15px;
            background-color: %s;
            color: %s;
            width: 420px;
            height: 220px;
            overflow: hidden;
        }
        .alert-title {
            font-size: 16px;
            font-weight: bold;
            color: #B22222;
            margin-bottom: 8px;
            border-bottom: 2px solid #B22222;
            padding-bottom: 5px;
        }
        .alert-type {
            font-size: 14px;
            font-weight: bold;
            color: #B22222;
            margin-bottom: 5px;
        }
        .rule-info {
            font-size: 12px;
            font-weight: bold;
            color: #000080;
            margin-bottom: 3px;
        }
        .risk-score {
            font-size: 12px;
            font-weight: bold;
            color: #006400;
            margin-bottom: 3px;
        }
        .time {
            font-size: 11px;
            color: #666;
            float: right;
            margin-top: -15px;
        }
        .details {
            font-size: 11px;
            color: #8B4513;
            margin: 8px 0;
            line-height: 1.3;
        }
        .message {
            font-size: 12px;
            margin: 10px 0;
            line-height: 1.4;
            max-height: 60px;
            overflow: hidden;
        }
        .close-btn {
            background-color: #B22222;
            color: white;
            border: none;
            padding: 5px 15px;
            cursor: pointer;
            float: right;
            margin-top: 10px;
            border-radius: 3px;
        }
        .close-btn:hover {
            background-color: #8B0000;
        }
    </style>
</head>
<body onload="positionWindow(); startTimer();">
    <div class="alert-title">🔔 %s</div>
    <div class="alert-type">🚨 SERVER RULE - %s</div>
    <div class="rule-info">🛡️ Rule: %s</div>
    <div class="risk-score">📊 Risk Score: %s</div>
    <div class="time">🕐 %s</div>
    <div class="details">⚠️ Details: %s</div>
    <div class="message">%s</div>
    <button class="close-btn" onclick="window.close()">Close</button>
</body>
<script>
function positionWindow() {
    var screenWidth = screen.width;
    var screenHeight = screen.height;
    var windowWidth = 420;
    var windowHeight = 220;
    var margin = 20;
    var taskbarHeight = 40;
    
    window.moveTo(screenWidth - windowWidth - margin, screenHeight - windowHeight - taskbarHeight - margin);
    window.resizeTo(windowWidth, windowHeight);
}

function startTimer() {
    setTimeout(function() {
        window.close();
    }, 10000); // 10 seconds
}
</script>
</html>`, bgColor, textColor, title, severityText, ruleName, riskScore, time.Now().Format("15:04:05"), details, message)

	err := os.WriteFile(htmlFile, []byte(htmlContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to create YARA alert HTML file: %w", err)
	}

	// Chạy HTA file
	cmd := exec.Command("mshta", htmlFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start YARA alert HTA: %w", err)
	}

	// Cleanup file sau 1 giây
	go func() {
		time.Sleep(1 * time.Second)
		os.Remove(htmlFile)
	}()

	wtn.logger.Info("YARA alert notification displayed successfully")
	return nil
}

// showHTMLNotification hiển thị notification bằng HTML + HTA
func (wtn *WindowsToastNotifier) showHTMLNotification(content *NotificationContent) error {
	// Tạo file HTML notification
	htmlFile := filepath.Join(wtn.scriptDir, "notification.hta")

	title := strings.ReplaceAll(content.Title, `"`, `&quot;`)
	message := strings.ReplaceAll(content.Message, `"`, `&quot;`)
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	severityText := wtn.getSeverityText(content.Severity)
	bgColor := wtn.getHTMLBackgroundColor(content.Severity)
	textColor := wtn.getHTMLTextColor(content.Severity)

	htmlContent := fmt.Sprintf(`
<html>
<head>
    <title>EDR Security Alert</title>
    <HTA:APPLICATION 
        ID="EDRAlert"
        APPLICATIONNAME="EDR Security Alert"
        BORDER="thin"
        BORDERSTYLE="normal"
        CAPTION="no"
        MAXIMIZEBUTTON="no"
        MINIMIZEBUTTON="no"
        SYSMENU="no"
        SCROLL="no"
        WINDOWSTATE="normal">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 15px;
            background-color: %s;
            color: %s;
            width: 370px;
            height: 170px;
            overflow: hidden;
        }
        .alert-title {
            font-size: 16px;
            font-weight: bold;
            color: #B22222;
            margin-bottom: 8px;
            border-bottom: 2px solid #B22222;
            padding-bottom: 5px;
        }
        .severity {
            font-size: 12px;
            font-weight: bold;
            color: #000080;
            margin-bottom: 5px;
        }
        .time {
            font-size: 11px;
            color: #666;
            float: right;
            margin-top: -15px;
        }
        .message {
            font-size: 12px;
            margin: 10px 0;
            line-height: 1.4;
            max-height: 80px;
            overflow: hidden;
        }
        .close-btn {
            background-color: #B22222;
            color: white;
            border: none;
            padding: 5px 15px;
            cursor: pointer;
            float: right;
            margin-top: 10px;
            border-radius: 3px;
        }
        .close-btn:hover {
            background-color: #8B0000;
        }
    </style>
</head>
<body onload="positionWindow(); startTimer();">
    <div class="alert-title">🚨 %s</div>
    <div class="severity">Severity: %s</div>
    <div class="time">%s</div>
    <div class="message">%s</div>
    <button class="close-btn" onclick="window.close();">Close</button>

    <script>
        function positionWindow() {
            var screenWidth = screen.availWidth;
            var screenHeight = screen.availHeight;
            var windowWidth = 400;
            var windowHeight = 200;
            var x = screenWidth - windowWidth - 20;
            var y = screenHeight - windowHeight - 20;
            
            window.resizeTo(windowWidth, windowHeight);
            window.moveTo(x, y);
        }
        
        function startTimer() {
            setTimeout(function() {
                window.close();
            }, 15000); // Auto close after 15 seconds
        }
        
        // Flash animation
        var flashCount = 0;
        function flashAlert() {
            if (flashCount < 6) {
                document.body.style.opacity = flashCount %% 2 === 0 ? '0.7' : '1';
                flashCount++;
                setTimeout(flashAlert, 200);
            } else {
                document.body.style.opacity = '1';
            }
        }
        setTimeout(flashAlert, 500);
    </script>
</body>
</html>
`, bgColor, textColor, title, severityText, time.Now().Format("15:04:05"), message)

	err := os.WriteFile(htmlFile, []byte(htmlContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to create HTML notification file: %w", err)
	}

	// Mở file HTA
	cmd := exec.Command("mshta.exe", htmlFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false} // Hiển thị cửa sổ

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to show HTML notification: %w", err)
	}

	wtn.logger.Info("HTML notification displayed successfully")

	// Xóa file sau 20 giây để cleanup
	go func() {
		time.Sleep(20 * time.Second)
		os.Remove(htmlFile)
	}()

	return nil
}

// showSimplePowerShellNotification hiển thị notification PowerShell đơn giản
func (wtn *WindowsToastNotifier) showSimplePowerShellNotification(content *NotificationContent) error {
	scriptPath := filepath.Join(wtn.scriptDir, "simple_notification.ps1")

	title := strings.ReplaceAll(content.Title, `"`, `'`)
	message := strings.ReplaceAll(content.Message, `"`, `'`)
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Normal", // Hiển thị để debug
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-File", scriptPath,
		"-Title", fmt.Sprintf(`"%s"`, title),
		"-Message", fmt.Sprintf(`"%s"`, message),
		"-Severity", fmt.Sprintf("%d", content.Severity),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		wtn.logger.Debug("PowerShell notification failed: %v, output: %s", err, string(output))
		return fmt.Errorf("PowerShell notification failed: %w", err)
	}

	wtn.logger.Debug("PowerShell notification output: %s", string(output))
	return nil
}

// showMsgNotification hiển thị notification bằng msg command (fallback cuối cùng)
func (wtn *WindowsToastNotifier) showMsgNotification(content *NotificationContent) error {
	title := content.Title
	message := fmt.Sprintf("%s\n\nSeverity: %s\nTime: %s\n\nThis alert will close automatically.",
		content.Message,
		wtn.getSeverityText(content.Severity),
		time.Now().Format("15:04:05"),
	)

	if len(message) > 300 {
		message = message[:300] + "..."
	}

	// Sử dụng PowerShell thay vì msg command
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
$result = [System.Windows.Forms.MessageBox]::Show("%s", "%s", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
`, strings.ReplaceAll(message, `"`, `'`), strings.ReplaceAll(title, `"`, `'`))

	cmd := exec.Command("powershell.exe", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}

	err := cmd.Start()
	if err != nil {
		wtn.logger.Error("PowerShell notification failed: %v", err)
		return fmt.Errorf("powershell notification failed: %w", err)
	}

	wtn.logger.Info("PowerShell notification sent")
	return nil
}

// createHTMLNotificationScript tạo script HTML (không dùng trong trường hợp này)
func (wtn *WindowsToastNotifier) createHTMLNotificationScript() error {
	// HTML notification sẽ được tạo dynamic, không cần script cố định
	wtn.logger.Debug("HTML notification will be generated dynamically")
	return nil
}

// createSimplePowerShellScript tạo PowerShell script đơn giản
func (wtn *WindowsToastNotifier) createSimplePowerShellScript() error {
	scriptContent := `param(
    [string]$Title = "EDR Alert",
    [string]$Message = "Security notification",
    [int]$Severity = 3
)

try {
    Write-Host "Starting PowerShell notification..."
    Write-Host "Title: $Title"
    Write-Host "Message: $Message"
    Write-Host "Severity: $Severity"

    # Try Windows Forms notification
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon = [System.Drawing.SystemIcons]::Warning
    $notify.Visible = $true
    $notify.BalloonTipTitle = $Title
    $notify.BalloonTipText = $Message

    switch ($Severity) {
        {$_ -le 2} { $notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info }
        3 { $notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning }
        {$_ -ge 4} { $notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Error }
    }

    $notify.ShowBalloonTip(10000)
    Write-Host "Balloon tip notification shown"

    # Keep notification visible for 10 seconds
    Start-Sleep -Seconds 10
    $notify.Visible = $false
    $notify.Dispose()
    
    Write-Host "Notification completed successfully"
}
catch {
    Write-Error "PowerShell notification failed: $($_.Exception.Message)"
    exit 1
}
`

	scriptPath := filepath.Join(wtn.scriptDir, "simple_notification.ps1")
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to create simple PowerShell script: %w", err)
	}

	wtn.logger.Info("Created simple PowerShell notification script: %s", scriptPath)
	return nil
}

// Helper functions
func (wtn *WindowsToastNotifier) getSeverityText(severity int) string {
	switch severity {
	case 1:
		return "LOW"
	case 2:
		return "LOW-MEDIUM"
	case 3:
		return "MEDIUM"
	case 4:
		return "HIGH"
	case 5:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (wtn *WindowsToastNotifier) getHTMLBackgroundColor(severity int) string {
	switch severity {
	case 1:
		return "#E6F3FF" // Light blue
	case 2:
		return "#E6FFE6" // Light green
	case 3:
		return "#FFFACD" // Light yellow
	case 4:
		return "#FFE4E1" // Light pink/salmon
	case 5:
		return "#FFB6C1" // Light red
	default:
		return "#F0F0F0" // Light gray
	}
}

func (wtn *WindowsToastNotifier) getHTMLTextColor(severity int) string {
	switch severity {
	case 1:
		return "#000080" // Dark blue
	case 2:
		return "#006400" // Dark green
	case 3:
		return "#B8860B" // Dark goldenrod
	case 4:
		return "#8B0000" // Dark red
	case 5:
		return "#800000" // Maroon
	default:
		return "#000000" // Black
	}
}

// TestNotification gửi notification thử nghiệm
func (wtn *WindowsToastNotifier) TestNotification() error {
	content := &NotificationContent{
		Title:     "🧪 EDR Test Alert",
		Message:   "This is a test notification displayed in the bottom-right corner of your screen using HTML popup. It should appear with colored background and auto-close after 15 seconds.",
		Severity:  4,
		Timestamp: time.Now(),
	}

	return wtn.SendNotification(content)
}

// showSimpleMessageBox hiển thị MessageBox đơn giản
func (wtn *WindowsToastNotifier) showSimpleMessageBox(content *NotificationContent) error {
	wtn.logger.Info("Attempting simple MessageBox...")

	// Tạo message đơn giản
	message := fmt.Sprintf("🚨 EDR Security Alert\n\n%s\n\nSeverity: %s\nTime: %s",
		content.Title,
		wtn.getSeverityText(content.Severity),
		time.Now().Format("15:04:05"))

	// Sử dụng PowerShell để hiển thị MessageBox
	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("%s", "EDR Security Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
`, strings.ReplaceAll(message, `"`, `'`))

	cmd := exec.Command("powershell.exe", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}

	err := cmd.Start()
	if err != nil {
		wtn.logger.Error("❌ Simple MessageBox failed: %v", err)
		return err
	}

	wtn.logger.Info("✅ Simple MessageBox displayed successfully")
	return nil
}

// TestYARAAlert gửi YARA alert test
func (wtn *WindowsToastNotifier) TestYARAAlert() error {
	content := &NotificationContent{
		Title:     "🚨 YARA Threat Detected",
		Message:   "Test YARA rule detection - vmdetect rule triggered",
		Severity:  5,
		Timestamp: time.Now(),
		ThreatInfo: &models.ThreatInfo{
			ThreatName:  "vmdetect",
			FilePath:    "C:\\test\\file.exe",
			Description: "Matched by external YARA rule: antidebug_antivm.yar",
		},
	}

	return wtn.SendNotification(content)
}
