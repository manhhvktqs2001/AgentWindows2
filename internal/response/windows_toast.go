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

// WindowsToastNotifier shows bottom-right alerts to the user
type WindowsToastNotifier struct {
    config               *config.ResponseConfig
    logger               *utils.Logger
    notificationCount    int
    failureCount         int
    lastNotification     time.Time
    disableNotifications bool
}

func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsToastNotifier {
    return &WindowsToastNotifier{config: cfg, logger: logger}
}

func (wtn *WindowsToastNotifier) Start() error {
    wtn.logger.Debug("Starting Windows Toast Notification System...")
    if !wtn.isPowerShellAvailable() {
        wtn.logger.Warn("PowerShell not available, notifications may be limited")
    }
    return nil
}

func (wtn *WindowsToastNotifier) Stop() {
    wtn.logger.Debug("Windows Toast Notification system stopped")
}

func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
    if wtn.disableNotifications {
        wtn.logger.Debug("Notifications disabled due to repeated failures")
        return fmt.Errorf("notifications disabled")
    }
    if time.Since(wtn.lastNotification) < 2*time.Second {
        wtn.logger.Debug("Rate limiting notification")
        return nil
    }

    wtn.lastNotification = time.Now()
    wtn.notificationCount++

    // Normalize/augment title and message to match desired style
    title := wtn.cleanString(content.Title)
    message := wtn.cleanString(content.Message)
    if title == "" {
        title = "EDR Security Alert"
    }
    if message == "" {
        message = "Security event detected"
    }
    if content.ThreatInfo != nil {
        rule := wtn.cleanString(content.ThreatInfo.ThreatName)
        if rule != "" {
            title = fmt.Sprintf("EDR Security Alert - %s", rule)
        }
        sevText := wtn.getSeverityText(content.Severity)
        message = fmt.Sprintf("A Security Threat Detected\nThreat: %s\nSeverity: %s", rule, sevText)
    }

    if len(title) > 100 {
        title = title[:100] + "..."
    }
    if len(message) > 300 {
        message = message[:300] + "..."
    }

    wtn.logger.Info("🚨 DISPLAYING SECURITY ALERT: %s", title)
    wtn.showConsoleAlert(title, message, content.Severity)

    var lastErr error
    // Preferred: bottom-right system tray balloon for ~3s
    if err := wtn.showSystemBalloonSafe(title, message); err == nil {
        wtn.logger.Info("✅ System balloon displayed")
        wtn.resetFailureCount()
        return nil
    } else {
        lastErr = err
        wtn.logger.Debug("System balloon failed: %v", err)
    }

    // Fallback: WPF corner popup (~3s)
    if err := wtn.showWpfCornerPopupSafe(title, message, content.Severity); err == nil {
        wtn.logger.Info("✅ WPF corner popup displayed")
        wtn.resetFailureCount()
        return nil
    } else {
        lastErr = err
        wtn.logger.Debug("WPF corner popup failed: %v", err)
    }

    // Optional fallback: native toast (may require AUMID/user session)
    if err := wtn.showNativeToastSafe(title, message); err == nil {
        wtn.logger.Info("✅ Native toast displayed")
        wtn.resetFailureCount()
        return nil
    } else {
        lastErr = err
        wtn.logger.Debug("Native toast failed: %v", err)
    }

    wtn.handleNotificationFailure(lastErr)
    return fmt.Errorf("failed to display notification via system balloon / WPF / toast")
}

func (wtn *WindowsToastNotifier) showConsoleAlert(title, message string, severity int) {
    icon := "🔔"
    switch severity {
    case 5:
        icon = "🚨"
    case 4:
        icon = "🟠"
    case 3:
        icon = "🟡"
    }
    fmt.Printf("\n%s %s %s\n", icon, icon, icon)
    fmt.Printf("Title: %s\n", title)
    fmt.Printf("Message: %s\n", message)
    fmt.Printf("Time: %s\n", time.Now().Format("15:04:05"))
    fmt.Printf("%s %s %s\n\n", icon, icon, icon)
    _ = os.Stdout.Sync()
}

func (wtn *WindowsToastNotifier) showSystemBalloonSafe(title, message string) error {
    if !wtn.isPowerShellAvailable() {
        return fmt.Errorf("PowerShell not available")
    }
    psScript := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    $icon = New-Object System.Windows.Forms.NotifyIcon
    $icon.Icon = [System.Drawing.SystemIcons]::Warning
    $icon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $icon.BalloonTipTitle = '%s'
    $icon.BalloonTipText = '%s'
    $icon.Visible = $true

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 3000
    $timer.Add_Tick({ $timer.Stop(); $icon.Visible = $false; $icon.Dispose(); [System.Windows.Forms.Application]::Exit() })

    $icon.ShowBalloonTip(3000)
    $timer.Start()
    [System.Windows.Forms.Application]::Run()
    exit 0
} catch {
    exit 1
}
`, title, message)
    return wtn.runPowerShellSafe(psScript, 6*time.Second)
}

func (wtn *WindowsToastNotifier) showWpfCornerPopupSafe(title, message string, severity int) error {
    if !wtn.isPowerShellAvailable() {
        return fmt.Errorf("PowerShell not available")
    }
    // Colors based on severity
    bgColor := "30, 30, 30"
    titleColor := "Orange"
    switch severity {
    case 5:
        bgColor = "60, 20, 20"
        titleColor = "Red"
    case 4:
        bgColor = "60, 40, 20"
        titleColor = "Orange"
    case 3:
        bgColor = "40, 40, 20"
        titleColor = "Yellow"
    }
    psScript := fmt.Sprintf(`
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

try {
    $screen = [System.Windows.SystemParameters]::WorkArea
    $width = 380
    $height = 120

    $window = New-Object System.Windows.Window
    $window.Width = $width
    $window.Height = $height
    $window.WindowStyle = 'None'
    $window.ResizeMode = 'NoResize'
    $window.Topmost = $true
    $window.AllowsTransparency = $true
    $window.Background = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromArgb(240, %s))
    $window.Left = $screen.Right - $width - 15
    $window.Top  = $screen.Bottom - $height - 15

    $border = New-Object System.Windows.Controls.Border
    $border.BorderBrush = [System.Windows.Media.Brushes]::%s
    $border.BorderThickness = 2
    $border.CornerRadius = 5
    $border.Margin = '5'

    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '10'
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))
    $grid.RowDefinitions.Add((New-Object System.Windows.Controls.RowDefinition))

    $titleBlock = New-Object System.Windows.Controls.TextBlock
    $titleBlock.Text = '%s'
    $titleBlock.FontSize = 14
    $titleBlock.FontWeight = 'Bold'
    $titleBlock.Foreground = [System.Windows.Media.Brushes]::%s
    $titleBlock.TextWrapping = 'Wrap'
    [System.Windows.Controls.Grid]::SetRow($titleBlock, 0)
    $grid.Children.Add($titleBlock) | Out-Null

    $msgBlock = New-Object System.Windows.Controls.TextBlock
    $msgBlock.Text = '%s'
    $msgBlock.Margin = '0,5,0,0'
    $msgBlock.FontSize = 11
    $msgBlock.TextWrapping = 'Wrap'
    $msgBlock.Foreground = [System.Windows.Media.Brushes]::LightGray
    [System.Windows.Controls.Grid]::SetRow($msgBlock, 1)
    $grid.Children.Add($msgBlock) | Out-Null

    $border.Child = $grid
    $window.Content = $border

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(3000)
    $timer.Add_Tick({ $timer.Stop(); $window.Close() })
    $window.Add_ContentRendered({ $timer.Start() })
    $window.Add_MouseLeftButtonDown({ $window.Close() })

    $window.ShowDialog() | Out-Null
    exit 0
} catch {
    exit 1
}
`, bgColor, titleColor, title, titleColor, message)
    return wtn.runPowerShellSafe(psScript, 6*time.Second)
}

func (wtn *WindowsToastNotifier) showNativeToastSafe(title, message string) error {
    if !wtn.isPowerShellAvailable() {
        return fmt.Errorf("PowerShell not available")
    }
    psScript := fmt.Sprintf(`
try {
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

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($template)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("EDR Security Agent")
    $notifier.Show($toast)
    Start-Sleep -Milliseconds 500
    exit 0
} catch {
    exit 1
}
`, title, message)
    return wtn.runPowerShellSafe(psScript, 5*time.Second)
}

func (wtn *WindowsToastNotifier) runPowerShellSafe(script string, timeout time.Duration) error {
    cmd := exec.Command("powershell.exe",
        "-WindowStyle", "Hidden",
        "-ExecutionPolicy", "Bypass",
        "-Sta",
        "-NoProfile",
        "-NonInteractive",
        "-Command", script,
    )
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

    done := make(chan error, 1)
    go func() { done <- cmd.Run() }()

    select {
    case err := <-done:
        return err
    case <-time.After(timeout):
        if cmd.Process != nil {
            _ = cmd.Process.Kill()
        }
        return fmt.Errorf("timeout")
    }
}

func (wtn *WindowsToastNotifier) isPowerShellAvailable() bool {
    cmd := exec.Command("powershell.exe", "-Command", "exit 0")
    cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    return cmd.Run() == nil
}

func (wtn *WindowsToastNotifier) handleNotificationFailure(err error) {
    wtn.failureCount++
    wtn.logger.Warn("Notification failure %d: %v", wtn.failureCount, err)
    if wtn.failureCount >= 10 {
        wtn.disableNotifications = true
        wtn.logger.Error("Disabling notifications due to repeated failures")
    }
}

func (wtn *WindowsToastNotifier) resetFailureCount() {
    if wtn.failureCount > 0 {
        wtn.failureCount = 0
        wtn.disableNotifications = false
    }
}

func (wtn *WindowsToastNotifier) cleanString(input string) string {
    if input == "" {
        return ""
    }
    input = strings.ReplaceAll(input, "`", "'")
    input = strings.ReplaceAll(input, `"`, `'`)
    input = strings.ReplaceAll(input, "\n", " ")
    input = strings.ReplaceAll(input, "\r", " ")
    input = strings.ReplaceAll(input, "\t", " ")
    input = strings.Join(strings.Fields(input), " ")
    return strings.TrimSpace(input)
}

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

// Test helpers
func (wtn *WindowsToastNotifier) TestNotification() error {
    content := &NotificationContent{
        Title:     "EDR Security Test",
        Message:   "This is a test notification from EDR Agent.",
        Severity:  3,
        Timestamp: time.Now(),
    }
    return wtn.SendNotification(content)
}

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

func (wtn *WindowsToastNotifier) GetStats() map[string]interface{} {
    return map[string]interface{}{
        "notification_count":     wtn.notificationCount,
        "failure_count":          wtn.failureCount,
        "notifications_disabled": wtn.disableNotifications,
        "last_notification":      wtn.lastNotification,
        "powershell_available":   wtn.isPowerShellAvailable(),
    }
}


