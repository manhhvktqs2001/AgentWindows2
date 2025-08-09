// File: internal/response/windows_toast.go
// Fix: Sửa lỗi hiển thị PowerShell balloon notification

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

// SendNotification hiển thị thông báo - ĐÃ FIX
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

	// FIX: Thử tất cả phương pháp hiển thị balloon với retry logic
	go func() {
		// Method 1: PowerShell Balloon (preferred)
		if err := wtn.showPowerShellBalloonFixed(content); err == nil {
			wtn.logger.Info("✅ PowerShell balloon notification displayed")
			return
		}

		// Method 2: Windows Forms MessageBox
		if err := wtn.showWindowsFormsMessageBox(content); err == nil {
			wtn.logger.Info("✅ Windows Forms notification displayed")
			return
		}

		// Method 3: PowerShell Toast (Windows 10+)
		if err := wtn.showPowerShellToast(content); err == nil {
			wtn.logger.Info("✅ PowerShell toast notification displayed")
			return
		}

		// Method 4: Command prompt popup
		wtn.showCommandPromptAlert(content)
		wtn.logger.Info("✅ Command prompt notification displayed")
	}()

	return nil
}

// FIX: showPowerShellBalloonFixed - Version đã sửa lỗi
func (wtn *WindowsToastNotifier) showPowerShellBalloonFixed(content *NotificationContent) error {
	title := wtn.escapeString(content.Title)
	message := wtn.escapeString(content.Message)

	// Rút gọn message nếu quá dài (balloon có giới hạn ký tự)
	if len(message) > 150 {
		message = message[:150] + "..."
	}

	// FIX: Script PowerShell được tối ưu hóa với error handling
	psScript := fmt.Sprintf(`
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $balloon = New-Object System.Windows.Forms.NotifyIcon
    
    # FIX: Sử dụng icon mặc định thay vì extract từ process
    $balloon.Icon = [System.Drawing.SystemIcons]::Warning
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $balloon.BalloonTipText = "%s"
    $balloon.BalloonTipTitle = "%s"
    $balloon.Visible = $true
    
    # FIX: Hiển thị balloon với timeout dài hơn
    $balloon.ShowBalloonTip(15000)
    
    # FIX: Đợi balloon hiển thị xong
    Start-Sleep -Seconds 12
    
    # Cleanup
    $balloon.Visible = $false
    $balloon.Dispose()
    
    Write-Host "Balloon notification displayed successfully"
    exit 0
} catch {
    Write-Error "Failed to show balloon: $_"
    exit 1
}
`, message, title)

	// FIX: Chạy PowerShell với các tham số tối ưu
	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-Command", psScript)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// FIX: Chạy và đợi kết quả
	err := cmd.Run()
	if err != nil {
		wtn.logger.Debug("PowerShell balloon failed: %v", err)
		return err
	}

	return nil
}

// FIX: Thêm method mới - Windows Forms MessageBox
func (wtn *WindowsToastNotifier) showWindowsFormsMessageBox(content *NotificationContent) error {
	title := wtn.escapeString(content.Title)
	message := wtn.escapeString(content.Message)

	if len(message) > 200 {
		message = message[:200] + "..."
	}

	psScript := fmt.Sprintf(`
try {
    Add-Type -AssemblyName System.Windows.Forms
    
    $result = [System.Windows.Forms.MessageBox]::Show(
        "%s", 
        "%s", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Warning,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
        [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly
    )
    
    Write-Host "MessageBox displayed successfully"
    exit 0
} catch {
    Write-Error "Failed to show MessageBox: $_"
    exit 1
}
`, message, title)

	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-Command", psScript)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Run()
}

// FIX: Thêm method mới - PowerShell Toast (Windows 10+)
func (wtn *WindowsToastNotifier) showPowerShellToast(content *NotificationContent) error {
	title := wtn.escapeString(content.Title)
	message := wtn.escapeString(content.Message)

	if len(message) > 100 {
		message = message[:100] + "..."
	}

	psScript := fmt.Sprintf(`
try {
    # FIX: Toast notification cho Windows 10+
    $template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>%s</text>
            <text>%s</text>
        </binding>
    </visual>
</toast>
"@

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("EDR Agent")
    $notifier.Show($toast)
    
    Write-Host "Toast notification displayed successfully"
    exit 0
} catch {
    Write-Error "Failed to show toast: $_"
    exit 1
}
`, title, message)

	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-Command", psScript)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	return cmd.Run()
}

// FIX: Helper function để escape strings an toàn
func (wtn *WindowsToastNotifier) escapeString(input string) string {
	// Thay thế các ký tự đặc biệt có thể gây lỗi PowerShell
	replacer := strings.NewReplacer(
		`"`, `'`,
		"`", "'",
		"$", "USD",
		"\r", " ",
		"\n", " ",
		"\t", " ",
	)
	return replacer.Replace(input)
}

// showCommandPromptAlert hiển thị alert bằng command prompt (fallback cuối cùng)
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
