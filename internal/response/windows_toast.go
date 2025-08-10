// internal/response/windows_toast.go
package response

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"

	"golang.org/x/sys/windows"
)

// WindowsToastNotifier provides native Windows toast notifications
type WindowsToastNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NOTIFYICONDATA structure for Windows system tray notifications
type NOTIFYICONDATA struct {
	CbSize           uint32
	HWnd             windows.Handle
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            windows.Handle
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UTimeout         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     windows.Handle
}

// Constants for notifications
const (
	NIM_ADD        = 0x00000000
	NIM_MODIFY     = 0x00000001
	NIM_DELETE     = 0x00000002
	NIM_SETFOCUS   = 0x00000003
	NIM_SETVERSION = 0x00000004

	NIF_MESSAGE = 0x00000001
	NIF_ICON    = 0x00000002
	NIF_TIP     = 0x00000004
	NIF_STATE   = 0x00000008
	NIF_INFO    = 0x00000010
	NIF_GUID    = 0x00000020

	NIIF_NONE       = 0x00000000
	NIIF_INFO       = 0x00000001
	NIIF_WARNING    = 0x00000002
	NIIF_ERROR      = 0x00000003
	NIIF_USER       = 0x00000004
	NIIF_NOSOUND    = 0x00000010
	NIIF_LARGE_ICON = 0x00000020

	IDI_APPLICATION = 32512
	IDI_WARNING     = 32515
	IDI_ERROR       = 32513
	IDI_INFORMATION = 32516
)

var (
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	user32  = windows.NewLazySystemDLL("user32.dll")

	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procLoadIconW        = user32.NewProc("LoadIconW")
)

func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsToastNotifier {
	return &WindowsToastNotifier{
		config: cfg,
		logger: logger,
	}
}

func (wtn *WindowsToastNotifier) Start() error {
	wtn.logger.Info("🚀 Starting Windows Toast Notifier...")
	return nil
}

func (wtn *WindowsToastNotifier) Stop() {
	wtn.logger.Info("🛑 Windows Toast Notifier stopped")
}

func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	// Show console alert first for immediate feedback
	wtn.showConsoleAlert(content)

	// Show system tray notification (appears in bottom-right corner)
	if err := wtn.showSystemTrayNotification(content); err != nil {
		wtn.logger.Warn("System tray notification failed: %v", err)
		// Fallback to MessageBox for critical alerts
		if content.Severity >= 4 {
			return wtn.showMessageBoxAlert(content)
		}
	}

	return nil
}

func (wtn *WindowsToastNotifier) showSystemTrayNotification(content *NotificationContent) error {
	// Create notification data
	var nid NOTIFYICONDATA
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = 0 // No parent window
	nid.UID = 1
	nid.UFlags = NIF_INFO | NIF_ICON | NIF_TIP

	// Load appropriate icon based on severity
	iconID := wtn.getIconForSeverity(content.Severity)
	hIcon, _, _ := procLoadIconW.Call(0, uintptr(iconID))
	nid.HIcon = windows.Handle(hIcon)

	// Set notification title and message
	title := wtn.prepareTitle(content)
	message := wtn.prepareMessage(content)

	// Convert strings to UTF16
	titleUTF16, _ := windows.UTF16FromString(title)
	messageUTF16, _ := windows.UTF16FromString(message)
	tipUTF16, _ := windows.UTF16FromString("EDR Agent")

	// Copy to fixed-size arrays
	copy(nid.SzInfoTitle[:], titleUTF16)
	copy(nid.SzInfo[:], messageUTF16)
	copy(nid.SzTip[:], tipUTF16)

	// Set notification flags based on severity
	nid.DwInfoFlags = wtn.getNotificationFlags(content.Severity)
	nid.UTimeout = uint32(content.Severity * 2000) // Duration based on severity

	// Show notification
	ret, _, _ := procShellNotifyIconW.Call(
		NIM_ADD,
		uintptr(unsafe.Pointer(&nid)),
	)

	if ret == 0 {
		return fmt.Errorf("failed to show system tray notification")
	}

	wtn.logger.Info("✅ System tray notification displayed: %s", title)

	// Auto-remove notification after timeout
	go func() {
		timeout := time.Duration(content.Severity*2+3) * time.Second
		time.Sleep(timeout)

		// Remove notification
		procShellNotifyIconW.Call(
			NIM_DELETE,
			uintptr(unsafe.Pointer(&nid)),
		)
	}()

	return nil
}

func (wtn *WindowsToastNotifier) showMessageBoxAlert(content *NotificationContent) error {
	title := wtn.prepareTitle(content)
	message := wtn.prepareMessage(content)

	// Determine MessageBox type based on severity
	mbType := uint32(0x00000040) // MB_ICONINFORMATION
	switch {
	case content.Severity >= 5:
		mbType = 0x00000010 // MB_ICONERROR
	case content.Severity >= 4:
		mbType = 0x00000030 // MB_ICONWARNING
	case content.Severity >= 3:
		mbType = 0x00000040 // MB_ICONINFORMATION
	}

	// Add topmost and foreground flags
	mbType |= 0x00010000 // MB_SETFOREGROUND
	mbType |= 0x00040000 // MB_TOPMOST

	messageBoxW := user32.NewProc("MessageBoxW")
	titlePtr, _ := windows.UTF16PtrFromString(title)
	messagePtr, _ := windows.UTF16PtrFromString(message)

	// Show in goroutine to avoid blocking
	go func() {
		ret, _, _ := messageBoxW.Call(
			0, // No parent window
			uintptr(unsafe.Pointer(messagePtr)),
			uintptr(unsafe.Pointer(titlePtr)),
			uintptr(mbType),
		)
		wtn.logger.Debug("MessageBox displayed, return: %d", ret)
	}()

	return nil
}

func (wtn *WindowsToastNotifier) showConsoleAlert(content *NotificationContent) {
	// Determine icon based on severity
	icon := "🔔"
	prefix := "INFO"
	switch {
	case content.Severity >= 5:
		icon = "🚨"
		prefix = "CRITICAL"
	case content.Severity >= 4:
		icon = "⚠️"
		prefix = "WARNING"
	case content.Severity >= 3:
		icon = "🟡"
		prefix = "ALERT"
	case content.Severity >= 2:
		icon = "🔵"
		prefix = "NOTICE"
	}

	// Display console alert
	fmt.Printf("\n%s %s: %s\n", icon, prefix, wtn.prepareTitle(content))
	if content.Message != "" {
		fmt.Printf("📄 %s\n", content.Message)
	}
	if content.ThreatInfo != nil {
		fmt.Printf("📁 File: %s\n", content.ThreatInfo.FilePath)
		fmt.Printf("🎯 Rule: %s\n", content.ThreatInfo.ThreatName)
	}
	fmt.Printf("⏰ Time: %s\n", time.Now().Format("15:04:05"))
	fmt.Printf("📊 Severity: %d/5\n\n", content.Severity)

	// Force output
	os.Stdout.Sync()

	// Add system beep for high severity
	if content.Severity >= 4 {
		wtn.playSystemBeep(content.Severity)
	}
}

func (wtn *WindowsToastNotifier) playSystemBeep(severity int) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	beep := kernel32.NewProc("Beep")

	// Different beep patterns based on severity
	patterns := map[int][]struct{ freq, duration int }{
		5: {{1000, 300}, {800, 300}, {1000, 300}}, // Critical: 3 urgent beeps
		4: {{800, 400}, {600, 400}},               // High: 2 warning beeps
		3: {{600, 500}},                           // Medium: 1 notice beep
	}

	pattern, exists := patterns[severity]
	if !exists {
		return
	}

	go func() {
		for i, beepInfo := range pattern {
			beep.Call(uintptr(beepInfo.freq), uintptr(beepInfo.duration))
			if i < len(pattern)-1 {
				time.Sleep(150 * time.Millisecond)
			}
		}
	}()
}

func (wtn *WindowsToastNotifier) getIconForSeverity(severity int) uint32 {
	switch {
	case severity >= 5:
		return IDI_ERROR
	case severity >= 4:
		return IDI_WARNING
	case severity >= 3:
		return IDI_INFORMATION
	default:
		return IDI_APPLICATION
	}
}

func (wtn *WindowsToastNotifier) getNotificationFlags(severity int) uint32 {
	switch {
	case severity >= 5:
		return NIIF_ERROR
	case severity >= 4:
		return NIIF_WARNING
	case severity >= 3:
		return NIIF_INFO
	default:
		return NIIF_INFO
	}
}

func (wtn *WindowsToastNotifier) prepareTitle(content *NotificationContent) string {
	if content.Title != "" {
		return content.Title
	}

	// Generate title based on content
	prefix := wtn.getSeverityPrefix(content.Severity)

	if content.ThreatInfo != nil {
		return fmt.Sprintf("%s EDR Alert - %s", prefix, content.ThreatInfo.ThreatName)
	}

	return fmt.Sprintf("%s EDR Security Alert", prefix)
}

func (wtn *WindowsToastNotifier) prepareMessage(content *NotificationContent) string {
	if content.Message != "" {
		return content.Message
	}

	// Generate message based on content
	if content.ThreatInfo != nil {
		fileName := ""
		if content.ThreatInfo.FilePath != "" {
			fileName = fmt.Sprintf("\nFile: %s", content.ThreatInfo.FilePath)
		}

		return fmt.Sprintf("Threat detected: %s%s\nSeverity: %d\nTime: %s",
			content.ThreatInfo.ThreatName,
			fileName,
			content.Severity,
			content.Timestamp.Format("15:04:05"))
	}

	return fmt.Sprintf("Security event detected at %s", content.Timestamp.Format("15:04:05"))
}

func (wtn *WindowsToastNotifier) getSeverityPrefix(severity int) string {
	switch {
	case severity >= 5:
		return "🚨 CRITICAL"
	case severity >= 4:
		return "⚠️ HIGH"
	case severity >= 3:
		return "🟡 MEDIUM"
	case severity >= 2:
		return "🔵 LOW"
	default:
		return "ℹ️ INFO"
	}
}

// Enhanced notification content structure
type NotificationContent struct {
	Title      string               `json:"title"`
	Message    string               `json:"message"`
	Severity   int                  `json:"severity"`
	Timestamp  time.Time            `json:"timestamp"`
	ThreatInfo *ThreatInfo          `json:"threat_info,omitempty"`
	Actions    []NotificationAction `json:"actions,omitempty"`
}

type ThreatInfo struct {
	ThreatName  string `json:"threat_name"`
	FilePath    string `json:"file_path"`
	Description string `json:"description"`
}

type NotificationAction struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"`
}
