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
	// Normalize/augment title and message to match the desired balloon style
	title := strings.TrimSpace(content.Title)
	message := strings.TrimSpace(content.Message)
	if content.ThreatInfo != nil {
		rule := wtn.cleanString(content.ThreatInfo.ThreatName)
		filePath := wtn.cleanString(content.ThreatInfo.FilePath)
		description := wtn.cleanString(content.ThreatInfo.Description)

		// Force title format: EDR Security Alert - <rule>
		title = fmt.Sprintf("EDR Security Alert - %s", rule)

		// Force message format: lines matching screenshot style
		sevText := wtn.getSeverityText(content.Severity)
		message = fmt.Sprintf("A Security Threat Detected\nThreat: %s\nSeverity: %s", rule, sevText)
		_ = filePath
		_ = description
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

	// Prefer WPF corner popup (bottom-right), then system tray balloon (3s), then native toast
	if err := wtn.showWpfCornerPopup(content); err == nil {
		wtn.logger.Info("✅ WPF corner popup displayed")
		return nil
	} else {
		wtn.logger.Debug("WPF corner popup failed: %v", err)
	}

	if err := wtn.showSystemBalloon(content); err == nil {
		wtn.logger.Info("✅ System balloon displayed")
		return nil
	} else {
		wtn.logger.Debug("System balloon failed: %v", err)
	}

	if err := wtn.showNativeToast(content); err == nil {
		wtn.logger.Info("✅ Native toast displayed")
		return nil
	} else {
		wtn.logger.Debug("Native toast failed: %v", err)
	}

	return fmt.Errorf("failed to display notification via wpf, balloon, or toast")
}

// showWpfCornerPopup shows a lightweight WPF window at bottom-right for ~3s
func (wtn *WindowsToastNotifier) showWpfCornerPopup(content *NotificationContent) error {
	title := wtn.cleanString(content.Title)
	message := wtn.cleanString(content.Message)

	if len(message) > 180 {
		message = message[:180] + "..."
	}

	psScript := fmt.Sprintf(`
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

try {
    $screen = [System.Windows.SystemParameters]::WorkArea
    $width = 380
    $height = 110

    $window = New-Object System.Windows.Window
    $window.Width = $width
    $window.Height = $height
    $window.WindowStyle = 'None'
    $window.ResizeMode = 'NoResize'
    $window.Topmost = $true
    $window.AllowsTransparency = $true
    $window.Background = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromArgb(230, 30, 30, 30))
    $window.Left = $screen.Right - $width - 12
    $window.Top  = $screen.Bottom - $height - 12

    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '12'

    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

    $titleBlock = New-Object System.Windows.Controls.TextBlock
    $titleBlock.Text = '%s'
    $titleBlock.FontSize = 16
    $titleBlock.FontWeight = 'Bold'
    $titleBlock.Foreground = [System.Windows.Media.Brushes]::Orange
    [System.Windows.Controls.Grid]::SetRow($titleBlock, 0)
    $grid.Children.Add($titleBlock) | Out-Null

    $msgBlock = New-Object System.Windows.Controls.TextBlock
    $msgBlock.Text = '%s'
    $msgBlock.Margin = '0,6,0,0'
    $msgBlock.TextWrapping = 'Wrap'
    $msgBlock.Foreground = [System.Windows.Media.Brushes]::White
    [System.Windows.Controls.Grid]::SetRow($msgBlock, 1)
    $grid.Children.Add($msgBlock) | Out-Null

    $window.Content = $grid

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(3200)
    $timer.Add_Tick({ $timer.Stop(); $window.Close() })

    $window.Add_ContentRendered({ $timer.Start() })
    $window.Show()
    [System.Windows.Threading.Dispatcher]::Run()
    exit 0
} catch {
    exit 1
}
`, title, message)

	return wtn.runPowerShell(psScript)
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
    $icon = New-Object System.Windows.Forms.NotifyIcon
    $icon.Icon = [System.Drawing.SystemIcons]::Warning
    $icon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $icon.BalloonTipTitle = "%s"
    $icon.BalloonTipText = "%s"
    $icon.Visible = $true

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 3500
    $timer.Add_Tick({
        $timer.Stop()
        $icon.Visible = $false
        $icon.Dispose()
        [System.Windows.Forms.Application]::Exit()
    })

    $icon.ShowBalloonTip(3000)
    $timer.Start()
    [System.Windows.Forms.Application]::Run()
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
		"-Sta",
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
