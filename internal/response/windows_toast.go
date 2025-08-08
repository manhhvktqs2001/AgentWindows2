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
	wtn.logger.Info("Starting Windows Toast Notification System...")

	// Tạo thư mục notifications
	err := os.MkdirAll(wtn.scriptDir, 0755)
	if err != nil {
		wtn.logger.Warn("Failed to create notification scripts directory: %v", err)
	}

	wtn.logger.Info("Windows Toast Notification system started successfully")
	return nil
}

// Stop dừng Windows toast notifier
func (wtn *WindowsToastNotifier) Stop() {
	wtn.logger.Info("Windows Toast Notification system stopped")
}

// SendNotification hiển thị thông báo
func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	wtn.logger.Info("🚨 DISPLAYING SECURITY ALERT: %s", content.Title)

	// In ra console NGAY LẬP TỨC
	fmt.Printf("\n")
	fmt.Printf("🚨🚨🚨 SECURITY ALERT 🚨🚨🚨\n")
	fmt.Printf("Title: %s\n", content.Title)
	fmt.Printf("Message:\n%s\n", content.Message)
	fmt.Printf("Severity: %s\n", wtn.getSeverityText(content.Severity))
	fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("🚨🚨🚨 END ALERT 🚨🚨🚨\n")
	fmt.Printf("\n")

	// Force flush console output
	os.Stdout.Sync()

	// Thử hiển thị Windows notification
	go func() {
		// Method 1: PowerShell Balloon Tip
		if err := wtn.showPowerShellBalloon(content); err == nil {
			wtn.logger.Info("✅ PowerShell balloon notification displayed")
			return
		}

		// Method 2: Simple MessageBox
		if err := wtn.showMessageBox(content); err == nil {
			wtn.logger.Info("✅ MessageBox notification displayed")
			return
		}

		// Method 3: Command prompt popup
		wtn.showCommandPromptAlert(content)
	}()

	return nil
}

// showPowerShellBalloon hiển thị balloon tip bằng PowerShell
func (wtn *WindowsToastNotifier) showPowerShellBalloon(content *NotificationContent) error {
	title := strings.ReplaceAll(content.Title, `"`, `'`)
	message := strings.ReplaceAll(content.Message, `"`, `'`)

	// Rút gọn message nếu quá dài
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$balloon = New-Object System.Windows.Forms.NotifyIcon
$path = Get-Process -id $pid | Select-Object -ExpandProperty Path
$balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)
$balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
$balloon.BalloonTipText = "%s"
$balloon.BalloonTipTitle = "%s"
$balloon.Visible = $true
$balloon.ShowBalloonTip(10000)

Start-Sleep 10
$balloon.Dispose()
`, message, title)

	cmd := exec.Command("powershell.exe", "-WindowStyle", "Hidden", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Start()
}

// showMessageBox hiển thị MessageBox đơn giản
func (wtn *WindowsToastNotifier) showMessageBox(content *NotificationContent) error {
	title := strings.ReplaceAll(content.Title, `"`, `'`)
	message := fmt.Sprintf("🚨 SECURITY ALERT\n\n%s\n\nSeverity: %s\nTime: %s\n\nThis alert will auto-close.",
		strings.ReplaceAll(content.Message, `"`, `'`),
		wtn.getSeverityText(content.Severity),
		time.Now().Format("15:04:05"))

	if len(message) > 400 {
		message = message[:400] + "..."
	}

	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("%s", "%s", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
`, message, title)

	cmd := exec.Command("powershell.exe", "-WindowStyle", "Hidden", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Start()
}

// showCommandPromptAlert hiển thị alert bằng command prompt
func (wtn *WindowsToastNotifier) showCommandPromptAlert(content *NotificationContent) {
	alertFile := filepath.Join(wtn.scriptDir, "alert.bat")

	batchContent := fmt.Sprintf(`@echo off
echo.
echo ==========================================
echo    🚨 EDR SECURITY ALERT 🚨
echo ==========================================
echo.
echo Title: %s
echo Severity: %s
echo Time: %s
echo.
echo %s
echo.
echo ==========================================
echo Press any key to close...
pause >nul
`,
		content.Title,
		wtn.getSeverityText(content.Severity),
		time.Now().Format("15:04:05"),
		content.Message)

	if err := os.WriteFile(alertFile, []byte(batchContent), 0644); err == nil {
		cmd := exec.Command("cmd.exe", "/c", "start", alertFile)
		cmd.Start()

		// Cleanup after 30 seconds
		go func() {
			time.Sleep(30 * time.Second)
			os.Remove(alertFile)
		}()
	}
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

// TestNotification gửi notification thử nghiệm
func (wtn *WindowsToastNotifier) TestNotification() error {
	content := &NotificationContent{
		Title:     "🧪 EDR Test Alert",
		Message:   "This is a test notification from EDR Agent. The system is working correctly and can display security alerts.",
		Severity:  4,
		Timestamp: time.Now(),
	}

	return wtn.SendNotification(content)
}

// TestYARAAlert gửi YARA alert test
func (wtn *WindowsToastNotifier) TestYARAAlert() error {
	content := &NotificationContent{
		Title:     "🚨 YARA Threat Detected",
		Message:   "Test YARA rule detection - A malicious file pattern has been detected on the system.",
		Severity:  5,
		Timestamp: time.Now(),
		ThreatInfo: &models.ThreatInfo{
			ThreatName:  "test_rule",
			FilePath:    "C:\\test\\file.exe",
			Description: "Test YARA rule triggered",
		},
	}

	return wtn.SendNotification(content)
}
