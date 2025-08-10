package response

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// RobustNotificationSystem - Completely rewritten notification system
type RobustNotificationSystem struct {
	config               *config.ResponseConfig
	logger               *utils.Logger
	notificationCount    int
	failureCount         int
	lastNotification     time.Time
	disableNotifications bool
	mu                   sync.Mutex

	// Performance tracking
	successCount  int
	timeoutCount  int
	fallbackCount int

	// Method availability cache
	wpfAvailable        *bool
	balloonAvailable    *bool
	toastAvailable      *bool
	powershellAvailable *bool
}

// Backwards-compatible alias to satisfy existing references
type WindowsToastNotifier = RobustNotificationSystem

func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *RobustNotificationSystem {
	return &RobustNotificationSystem{
		config: cfg,
		logger: logger,
	}
}

func (rns *RobustNotificationSystem) Start() error {
	rns.logger.Info("🚀 Starting Robust Notification System...")

	// Pre-check all notification methods
	go rns.preCheckNotificationMethods()

	return nil
}

func (rns *RobustNotificationSystem) Stop() {
	rns.logger.Info("🛑 Robust Notification System stopped")
}

// Pre-check all notification methods to avoid runtime failures
func (rns *RobustNotificationSystem) preCheckNotificationMethods() {
	rns.mu.Lock()
	defer rns.mu.Unlock()

	// Check PowerShell availability
	available := rns.checkPowerShellQuick()
	rns.powershellAvailable = &available

	if available {
		// Quick test of each method
		wpf := rns.testWPFMethod()
		rns.wpfAvailable = &wpf

		balloon := rns.testBalloonMethod()
		rns.balloonAvailable = &balloon

		toast := rns.testToastMethod()
		rns.toastAvailable = &toast

		rns.logger.Info("📊 Notification methods available: WPF=%v, Balloon=%v, Toast=%v", wpf, balloon, toast)
	} else {
		rns.logger.Debug("⚠️ PowerShell not available - notifications will use basic fallback")
		false_val := false
		rns.wpfAvailable = &false_val
		rns.balloonAvailable = &false_val
		rns.toastAvailable = &false_val
	}
}

func (rns *RobustNotificationSystem) SendNotification(content *NotificationContent) error {
	rns.mu.Lock()
	defer rns.mu.Unlock()

	if rns.disableNotifications {
		rns.logger.Debug("Notifications disabled due to repeated failures")
		return fmt.Errorf("notifications disabled")
	}

	// Rate limiting
	if time.Since(rns.lastNotification) < 500*time.Millisecond {
		rns.logger.Debug("Rate limiting notification")
		return nil
	}

	rns.lastNotification = time.Now()
	rns.notificationCount++

	// Prepare content
	title, message := rns.prepareContent(content)

	rns.logger.Info("🚨 DISPLAYING SECURITY ALERT: %s", title)
	rns.showConsoleAlert(title, message, content.Severity)

	// Show ONLY bottom-right system tray balloon (~3s). Fast and reliable.
	if err := rns.showQuickBalloon(title, message); err == nil {
		rns.logger.Info("✅ System balloon displayed")
		rns.successCount++
		rns.resetFailureCount()
		return nil
	}

	// Fallback: WPF corner popup (~3s)
	if err := rns.showInstantWPF(title, message, content.Severity); err == nil {
		rns.logger.Info("✅ WPF corner popup displayed")
		rns.successCount++
		rns.resetFailureCount()
		return nil
	}

	// Final fallback: console
	rns.showConsoleFallback(title, message, content.Severity)
	rns.fallbackCount++
	rns.resetFailureCount()
	return nil
}

func (rns *RobustNotificationSystem) prepareContent(content *NotificationContent) (string, string) {
	title := rns.cleanString(content.Title)
	message := rns.cleanString(content.Message)

	if title == "" {
		title = "EDR Security Alert"
	}

	if message == "" {
		message = "Security event detected"
	}

	// Format based on threat info
	if content.ThreatInfo != nil {
		rule := rns.cleanString(content.ThreatInfo.ThreatName)
		if rule != "" {
			title = fmt.Sprintf("EDR Security Alert - %s", rule)
		}
		sevText := rns.getSeverityText(content.Severity)
		message = fmt.Sprintf("A Security Threat Detected\nThreat: %s\nSeverity: %s", rule, sevText)
	}

	// Truncate if too long
	if len(title) > 60 {
		title = title[:60] + "..."
	}
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	return title, message
}

// Instant WPF method with minimal timeout
func (rns *RobustNotificationSystem) showInstantWPF(title, message string, severity int) error {

	bgColor, titleColor := rns.getSeverityColors(severity)

	psScript := fmt.Sprintf(`
try {
    Add-Type -AssemblyName PresentationFramework
    $workArea = [System.Windows.SystemParameters]::WorkArea
    $window = New-Object System.Windows.Window
    $window.Title = 'EDR'
    $window.Width = 350
    $window.Height = 120
    $window.Left = $workArea.Right - 370
    $window.Top = $workArea.Bottom - 140  
    $window.WindowStyle = 'None'
    $window.Topmost = $true
    $window.AllowsTransparency = $true
    $window.Background = [System.Windows.Media.SolidColorBrush]([System.Windows.Media.Color]::FromArgb(240, %s))
    
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Margin = '10'
    
    $titleBlock = New-Object System.Windows.Controls.TextBlock
    $titleBlock.Text = '%s'
    $titleBlock.FontSize = 12
    $titleBlock.FontWeight = 'Bold'
    $titleBlock.Foreground = [System.Windows.Media.Brushes]::%s
    $titleBlock.Margin = '0,0,0,5'
    $grid.Children.Add($titleBlock)
    
    $messageBlock = New-Object System.Windows.Controls.TextBlock  
    $messageBlock.Text = '%s'
    $messageBlock.FontSize = 10
    $messageBlock.Foreground = [System.Windows.Media.Brushes]::LightGray
    $messageBlock.Margin = '0,20,0,0'
    $grid.Children.Add($messageBlock)
    
    $window.Content = $grid
    $window.Show()
    
    Start-Sleep -Milliseconds 2500
    $window.Close()
    exit 0
} catch { exit 1 }
`, bgColor, title, titleColor, message)

	return rns.runPowerShellQuick(psScript, 3*time.Second)
}

// Quick balloon method
func (rns *RobustNotificationSystem) showQuickBalloon(title, message string) error {

	psScript := fmt.Sprintf(`
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $icon = New-Object System.Windows.Forms.NotifyIcon
    $icon.Icon = [System.Drawing.SystemIcons]::Warning
    $icon.BalloonTipTitle = '%s'
    $icon.BalloonTipText = '%s'  
    $icon.Visible = $true

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 3200
    $timer.Add_Tick({ $timer.Stop(); $icon.Visible = $false; $icon.Dispose(); [System.Windows.Forms.Application]::Exit() })

    $icon.ShowBalloonTip(3000)
    $timer.Start()
    [System.Windows.Forms.Application]::Run()
    exit 0
} catch { exit 1 }
`, title, message)

	return rns.runPowerShellQuick(psScript, 5*time.Second)
}

// Basic MessageBox that always works
func (rns *RobustNotificationSystem) showBasicMessageBox(title, message string, severity int) error {
	iconType := "Information"
	if severity >= 4 {
		iconType = "Warning"
	}
	if severity >= 5 {
		iconType = "Error"
	}

	psScript := fmt.Sprintf(`
try {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show('%s', '%s', 'OK', '%s')
    exit 0
} catch { exit 1 }
`, message, title, iconType)

	return rns.runPowerShellQuick(psScript, 2*time.Second)
}

// Quick PowerShell execution with aggressive timeout
func (rns *RobustNotificationSystem) runPowerShellQuick(script string, timeout time.Duration) error {
	exe := rns.resolvePowerShellPath()
	cmd := exec.Command(exe,
		"-WindowStyle", "Hidden",
		"-ExecutionPolicy", "Bypass",
		"-Sta",
		"-NoProfile",
		"-NonInteractive",
		"-Command", script)

	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	// Use channel for quick timeout handling
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()
		done <- cmd.Run()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		rns.timeoutCount++
		return fmt.Errorf("timeout after %v", timeout)
	}
}

// Quick PowerShell availability check
func (rns *RobustNotificationSystem) checkPowerShellQuick() bool {
	exe := rns.resolvePowerShellPath()
	cmd := exec.Command(exe, "-Command", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case err := <-done:
		return err == nil
	case <-time.After(1 * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return false
	}
}

// resolvePowerShellPath tries multiple locations to find a usable PowerShell
func (rns *RobustNotificationSystem) resolvePowerShellPath() string {
	// Prefer Windows PowerShell full path to avoid PATH and WOW64 redirection issues
	candidates := []string{
		// 64-bit PowerShell from 32-bit process via Sysnative
		os.ExpandEnv(`%windir%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe`),
		// Standard 64/32-bit path
		os.ExpandEnv(`%windir%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`),
		// PowerShell 7 (pwsh) if installed
		"pwsh.exe",
		// Fallback to PATH
		"powershell.exe",
	}
	for _, p := range candidates {
		if p == "powershell.exe" || p == "pwsh.exe" {
			// rely on PATH lookup
			if _, err := exec.LookPath(p); err == nil {
				return p
			}
			continue
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return "powershell.exe"
}

// Test methods quickly
func (rns *RobustNotificationSystem) testWPFMethod() bool {
	script := `try { Add-Type -AssemblyName PresentationFramework; exit 0 } catch { exit 1 }`
	return rns.runPowerShellQuick(script, 2*time.Second) == nil
}

func (rns *RobustNotificationSystem) testBalloonMethod() bool {
	script := `try { Add-Type -AssemblyName System.Windows.Forms; exit 0 } catch { exit 1 }`
	return rns.runPowerShellQuick(script, 2*time.Second) == nil
}

func (rns *RobustNotificationSystem) testToastMethod() bool {
	script := `try { [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; exit 0 } catch { exit 1 }`
	return rns.runPowerShellQuick(script, 2*time.Second) == nil
}

func (rns *RobustNotificationSystem) getSeverityColors(severity int) (string, string) {
	switch severity {
	case 5:
		return "80, 20, 20", "Red" // Critical - Dark red background, red text
	case 4:
		return "80, 40, 20", "Orange" // High - Dark orange background, orange text
	case 3:
		return "60, 60, 20", "Yellow" // Medium - Dark yellow background, yellow text
	case 2:
		return "40, 40, 60", "LightBlue" // Low-Medium - Dark blue background, light blue text
	default:
		return "40, 40, 40", "LightGray" // Low - Dark gray background, light gray text
	}
}

func (rns *RobustNotificationSystem) showConsoleAlert(title, message string, severity int) {
	icon := "🔔"
	switch severity {
	case 5:
		icon = "🚨"
	case 4:
		icon = "🟠"
	case 3:
		icon = "🟡"
	case 2:
		icon = "🔵"
	}

	fmt.Printf("\n%s %s\n", icon, title)
	fmt.Printf("📄 %s\n", message)
	fmt.Printf("⏰ %s\n\n", time.Now().Format("15:04:05"))
	_ = os.Stdout.Sync()
}

func (rns *RobustNotificationSystem) showConsoleFallback(title, message string, severity int) {
	fmt.Printf("\n🖥️ CONSOLE NOTIFICATION (Fallback)\n")
	fmt.Printf("📢 %s\n", title)
	fmt.Printf("📝 %s\n", message)
	fmt.Printf("🎚️ Severity: %d\n", severity)
	fmt.Printf("⏰ Time: %s\n\n", time.Now().Format("15:04:05"))
	_ = os.Stdout.Sync()
}

func (rns *RobustNotificationSystem) handleNotificationFailure(err error) {
	rns.failureCount++
	rns.logger.Warn("Notification failure %d: %v", rns.failureCount, err)

	// More lenient failure threshold
	if rns.failureCount >= 10 {
		rns.disableNotifications = true
		rns.logger.Error("Disabling notifications due to repeated failures")
	}
}

func (rns *RobustNotificationSystem) resetFailureCount() {
	if rns.failureCount > 0 {
		rns.failureCount = 0
		rns.disableNotifications = false
	}
}

func (rns *RobustNotificationSystem) cleanString(input string) string {
	if input == "" {
		return ""
	}
	// Escape single quotes for PowerShell
	input = strings.ReplaceAll(input, "'", "''")
	input = strings.ReplaceAll(input, "`", "'")
	input = strings.ReplaceAll(input, "\n", " ")
	input = strings.ReplaceAll(input, "\r", " ")
	input = strings.ReplaceAll(input, "\t", " ")
	input = strings.Join(strings.Fields(input), " ")
	return strings.TrimSpace(input)
}

func (rns *RobustNotificationSystem) getSeverityText(severity int) string {
	switch severity {
	case 1:
		return "LOW"
	case 2:
		return "LOW-MED"
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
func (rns *RobustNotificationSystem) TestNotification() error {
	content := &NotificationContent{
		Title:     "EDR Test Alert",
		Message:   "Test notification from EDR Agent",
		Severity:  3,
		Timestamp: time.Now(),
	}
	return rns.SendNotification(content)
}

func (rns *RobustNotificationSystem) TestYARAAlert() error {
	content := &NotificationContent{
		Title:     "YARA Detection Test",
		Message:   "Test security alert notification",
		Severity:  5,
		Timestamp: time.Now(),
		ThreatInfo: &models.ThreatInfo{
			ThreatName:  "test_detection_rule",
			FilePath:    "C:\\temp\\test.exe",
			Description: "Test threat detection",
		},
	}
	return rns.SendNotification(content)
}

func (rns *RobustNotificationSystem) GetStats() map[string]interface{} {
	rns.mu.Lock()
	defer rns.mu.Unlock()

	return map[string]interface{}{
		"notification_count":     rns.notificationCount,
		"success_count":          rns.successCount,
		"failure_count":          rns.failureCount,
		"timeout_count":          rns.timeoutCount,
		"fallback_count":         rns.fallbackCount,
		"notifications_disabled": rns.disableNotifications,
		"last_notification":      rns.lastNotification,
		"powershell_available":   rns.powershellAvailable,
		"wpf_available":          rns.wpfAvailable,
		"balloon_available":      rns.balloonAvailable,
		"toast_available":        rns.toastAvailable,
	}
}
