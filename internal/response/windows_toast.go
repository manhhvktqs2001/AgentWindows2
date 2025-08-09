// File: internal/response/windows_toast.go
// SIMPLE: Windows Native Toast Notification - Bottom Right Corner

package response

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// WindowsToastNotifier displays native Windows notifications
type WindowsToastNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewWindowsToastNotifier creates a new Windows toast notifier
func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsToastNotifier {
	return &WindowsToastNotifier{
		config: cfg,
		logger: logger,
	}
}

// Start initializes the Windows toast notifier
func (wtn *WindowsToastNotifier) Start() error {
	wtn.logger.Info("Starting Windows Native Toast Notification System...")
	return nil
}

// Stop stops the Windows toast notifier
func (wtn *WindowsToastNotifier) Stop() {
	wtn.logger.Info("Windows Toast Notification system stopped")
}

// SendNotification displays native Windows notification
func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	// Normalize/augment title and message to include rule name and details
	title := strings.TrimSpace(content.Title)
	message := strings.TrimSpace(content.Message)
	if content.ThreatInfo != nil {
		rule := wtn.cleanString(content.ThreatInfo.ThreatName)
		filePath := wtn.cleanString(content.ThreatInfo.FilePath)
		description := wtn.cleanString(content.ThreatInfo.Description)

		lowerTitle := strings.ToLower(title)
		if title == "" || strings.Contains(lowerTitle, "yara threat detected") || strings.Contains(lowerTitle, "security alert") {
			title = fmt.Sprintf("YARA: %s", rule)
		}

		if message == "" {
			// Concise detail for the popup; long text will be trimmed by toast/balloon methods
			base := fmt.Sprintf("Rule: %s\nFile: %s", rule, filePath)
			if description != "" {
				message = base + "\n" + description
			} else {
				message = base
			}
		}
	}

	// Apply back after cleaning
	content.Title = wtn.cleanString(title)
	content.Message = wtn.cleanString(message)

	wtn.logger.Info("🚨 DISPLAYING SECURITY ALERT: %s", content.Title)

	// Print to console immediately
	fmt.Printf("\n🚨🚨🚨 SECURITY ALERT 🚨🚨🚨\n")
	fmt.Printf("Title: %s\n", content.Title)
	fmt.Printf("Severity: %s\n", wtn.getSeverityText(content.Severity))
	if content.ThreatInfo != nil {
		fmt.Printf("Rule: %s\n", content.ThreatInfo.ThreatName)
		if content.ThreatInfo.FilePath != "" {
			fmt.Printf("File: %s\n", content.ThreatInfo.FilePath)
		}
	}
	fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")
	os.Stdout.Sync()

	// Try native toast first
	if err := wtn.showNativeToast(content); err == nil {
		wtn.logger.Info("✅ Native toast displayed")
		return nil
	} else {
		wtn.logger.Debug("Native toast failed: %v", err)
	}

	// Fallback to bottom-right system tray balloon
	if err := wtn.showSystemBalloon(content); err == nil {
		wtn.logger.Info("✅ System balloon displayed")
		return nil
	} else {
		wtn.logger.Debug("System balloon failed: %v", err)
	}

	// Last resort: simple msg broadcast (best-effort, no error check)
	wtn.showSimpleNotification(content)
	return fmt.Errorf("all notification methods failed")
}

// showNativeToast shows Windows 10+ native toast notification
func (wtn *WindowsToastNotifier) showNativeToast(content *NotificationContent) error {
	title := wtn.cleanString(content.Title)
	message := wtn.cleanString(content.Message)

	// Keep message short for toast
	if len(message) > 80 {
		message = message[:80] + "..."
	}

	// Use PowerShell to show Windows 10 toast
	psScript := fmt.Sprintf(`
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$null = [Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime]
$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]

$template = @"
<toast duration="short">
    <visual>
        <binding template="ToastGeneric">
            <text>%s</text>
            <text>%s</text>
        </binding>
    </visual>
    <audio silent="false"/>
</toast>
"@

try {
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("EDR Security Agent")
    $notifier.Show($toast)
    exit 0
} catch {
    exit 1
}
`, title, message)

	return wtn.runPowerShell(psScript)
}

// showSystemBalloon shows system tray balloon notification
func (wtn *WindowsToastNotifier) showSystemBalloon(content *NotificationContent) error {
	title := wtn.cleanString(content.Title)
	message := wtn.cleanString(content.Message)

	// Keep message short for balloon
	if len(message) > 120 {
		message = message[:120] + "..."
	}

	psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Warning
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $balloon.BalloonTipTitle = "%s"
    $balloon.BalloonTipText = "%s"
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(3000)
    Start-Sleep -Seconds 4
    $balloon.Visible = $false
    $balloon.Dispose()
    exit 0
} catch {
    exit 1
}
`, title, message)

	return wtn.runPowerShell(psScript)
}

// showSimpleNotification shows a simple notification using msg command
func (wtn *WindowsToastNotifier) showSimpleNotification(content *NotificationContent) {
	title := wtn.cleanString(content.Title)
	message := wtn.cleanString(content.Message)

	// Keep message very short
	if len(message) > 100 {
		message = message[:100] + "..."
	}

	// Use Windows msg command as last resort
	cmd := exec.Command("msg", "*", fmt.Sprintf("%s\n\n%s", title, message))
	cmd.Run()
}

// runPowerShell executes PowerShell script with timeout
func (wtn *WindowsToastNotifier) runPowerShell(script string) error {
	cmd := exec.Command("powershell.exe",
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-NoProfile",
		"-Command", script)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// Run with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return fmt.Errorf("timeout")
	}
}

// cleanString cleans string for safe use in PowerShell
func (wtn *WindowsToastNotifier) cleanString(input string) string {
	// Remove problematic characters
	input = strings.ReplaceAll(input, `"`, `'`)
	input = strings.ReplaceAll(input, `$`, `USD`)
	input = strings.ReplaceAll(input, "`", "'")
	input = strings.ReplaceAll(input, "\n", " ")
	input = strings.ReplaceAll(input, "\r", " ")
	input = strings.ReplaceAll(input, "\t", " ")

	// Remove extra spaces
	for strings.Contains(input, "  ") {
		input = strings.ReplaceAll(input, "  ", " ")
	}

	return strings.TrimSpace(input)
}

// getSeverityText returns severity text
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

// TestNotification sends a test notification
func (wtn *WindowsToastNotifier) TestNotification() error {
	content := &NotificationContent{
		Title:     "EDR Security Test",
		Message:   "This is a test notification from EDR Agent.",
		Severity:  3,
		Timestamp: time.Now(),
	}

	return wtn.SendNotification(content)
}

// TestYARAAlert sends a YARA alert test
func (wtn *WindowsToastNotifier) TestYARAAlert() error {
	content := &NotificationContent{
		Title:     "YARA Threat Detected",
		Message:   "Security threat detected. File has been quarantined.",
		Severity:  5,
		Timestamp: time.Now(),
		ThreatInfo: &models.ThreatInfo{
			ThreatName:  "test_rule",
			FilePath:    "C:\\temp\\suspicious.exe",
			Description: "Test threat detection",
		},
	}

	return wtn.SendNotification(content)
}
