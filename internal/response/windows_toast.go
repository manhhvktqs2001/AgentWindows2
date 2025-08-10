// Alternative notification method không cần PowerShell
// File: internal/response/windows_toast.go

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

// Native Windows notification sử dụng API trực tiếp
type NativeNotificationSystem struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

func NewNativeNotificationSystem(cfg *config.ResponseConfig, logger *utils.Logger) *NativeNotificationSystem {
	return &NativeNotificationSystem{
		config: cfg,
		logger: logger,
	}
}

func (nns *NativeNotificationSystem) Start() error {
	nns.logger.Info("🚀 Starting Native Notification System (No PowerShell required)...")
	return nil
}

func (nns *NativeNotificationSystem) Stop() {
	nns.logger.Info("🛑 Native Notification System stopped")
}

func (nns *NativeNotificationSystem) SendNotification(content *NotificationContent) error {
	title, message := nns.prepareContent(content)

	nns.logger.Info("🚨 NATIVE ALERT: %s", title)
	nns.showConsoleAlert(title, message, content.Severity)

	// Thử các method native theo thứ tự
	methods := []func(string, string, int) error{
		nns.showMessageBoxAlert,
		nns.showSystemBeepAlert,
		nns.showConsoleFlashAlert,
	}

	for i, method := range methods {
		if err := method(title, message, content.Severity); err == nil {
			nns.logger.Info("✅ Native method %d succeeded", i+1)
			return nil
		}
	}

	return nil
}

// MessageBox alert - luôn hoạt động
func (nns *NativeNotificationSystem) showMessageBoxAlert(title, message string, severity int) error {
	// Chỉ hiển thị MessageBox cho severity cao để không spam
	if severity < 4 {
		return fmt.Errorf("severity too low for MessageBox")
	}

	iconType := uint32(0x00000040) // MB_ICONINFORMATION
	if severity >= 4 {
		iconType = 0x00000030 // MB_ICONWARNING
	}
	if severity >= 5 {
		iconType = 0x00000010 // MB_ICONERROR
	}

	user32 := windows.NewLazySystemDLL("user32.dll")
	messageBoxW := user32.NewProc("MessageBoxW")

	titlePtr, _ := windows.UTF16PtrFromString(fmt.Sprintf("EDR Alert [Sev:%d]", severity))
	messagePtr, _ := windows.UTF16PtrFromString(fmt.Sprintf("%s\n\n%s", title, message))

	// Hiển thị MessageBox trong goroutine để không block
	go func() {
		ret, _, _ := messageBoxW.Call(
			0, // No parent
			uintptr(unsafe.Pointer(messagePtr)),
			uintptr(unsafe.Pointer(titlePtr)),
			uintptr(iconType|0x00000000|0x00010000), // MB_OK | MB_SETFOREGROUND
		)
		nns.logger.Debug("MessageBox displayed, return: %d", ret)
	}()

	return nil
}

// System beep alert
func (nns *NativeNotificationSystem) showSystemBeepAlert(title, message string, severity int) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	beep := kernel32.NewProc("Beep")

	// Beep pattern dựa trên severity
	patterns := map[int][]struct{ freq, duration int }{
		5: {{1000, 200}, {800, 200}, {1000, 200}}, // Critical: 3 beeps
		4: {{800, 300}, {600, 300}},               // High: 2 beeps
		3: {{600, 400}},                           // Medium: 1 beep
		2: {{400, 200}},                           // Low: short beep
		1: {{300, 100}},                           // Very low: very short
	}

	pattern, exists := patterns[severity]
	if !exists {
		pattern = patterns[3] // Default medium
	}

	go func() {
		for _, beepInfo := range pattern {
			beep.Call(uintptr(beepInfo.freq), uintptr(beepInfo.duration))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	nns.logger.Info("🔊 System beep alert played (severity %d)", severity)
	return nil
}

// Console flash alert - flash console window
func (nns *NativeNotificationSystem) showConsoleFlashAlert(title, message string, severity int) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	user32 := windows.NewLazySystemDLL("user32.dll")

	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	flashWindow := user32.NewProc("FlashWindow")

	// Get console window handle
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		return fmt.Errorf("no console window")
	}

	// Flash window based on severity
	flashCount := severity
	if flashCount > 5 {
		flashCount = 5
	}

	go func() {
		for i := 0; i < flashCount; i++ {
			flashWindow.Call(hwnd, 1) // Flash
			time.Sleep(200 * time.Millisecond)
			flashWindow.Call(hwnd, 0) // Stop flash
			time.Sleep(200 * time.Millisecond)
		}
	}()

	nns.logger.Info("⚡ Console flash alert (severity %d)", severity)
	return nil
}

// Tray icon notification sử dụng Shell_NotifyIcon
func (nns *NativeNotificationSystem) showTrayIconAlert(title, message string, severity int) error {
	// Struct cho NOTIFYICONDATA
	type NOTIFYICONDATA struct {
		cbSize           uint32
		hWnd             uintptr
		uID              uint32
		uFlags           uint32
		uCallbackMessage uint32
		hIcon            uintptr
		szTip            [128]uint16
		dwState          uint32
		dwStateMask      uint32
		szInfo           [256]uint16
		uVersion         uint32
		szInfoTitle      [64]uint16
		dwInfoFlags      uint32
		guidItem         [16]byte
		hBalloonIcon     uintptr
	}

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	user32 := windows.NewLazySystemDLL("user32.dll")

	shell_NotifyIconW := shell32.NewProc("Shell_NotifyIconW")
	loadIconW := user32.NewProc("LoadIconW")

	// Load system icon
	hIcon, _, _ := loadIconW.Call(0, 32516) // IDI_WARNING

	// Prepare notification data
	var nid NOTIFYICONDATA
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = 0
	nid.uID = 1
	nid.uFlags = 0x00000010 | 0x00000002 | 0x00000001 // NIF_INFO | NIF_ICON | NIF_MESSAGE
	nid.hIcon = hIcon

	// Convert strings to UTF16
	titleUTF16, _ := windows.UTF16FromString(title)
	messageUTF16, _ := windows.UTF16FromString(message)

	copy(nid.szInfoTitle[:], titleUTF16)
	copy(nid.szInfo[:], messageUTF16)

	nid.dwInfoFlags = 1 // NIIF_INFO
	if severity >= 4 {
		nid.dwInfoFlags = 2 // NIIF_WARNING
	}
	if severity >= 5 {
		nid.dwInfoFlags = 3 // NIIF_ERROR
	}

	// Show notification
	ret, _, _ := shell_NotifyIconW.Call(0, uintptr(unsafe.Pointer(&nid))) // NIM_ADD
	if ret == 0 {
		return fmt.Errorf("failed to show tray notification")
	}

	// Auto-remove after 5 seconds
	go func() {
		time.Sleep(5 * time.Second)
		shell_NotifyIconW.Call(2, uintptr(unsafe.Pointer(&nid))) // NIM_DELETE
	}()

	nns.logger.Info("📱 Tray icon notification displayed")
	return nil
}

// Helper methods
func (nns *NativeNotificationSystem) prepareContent(content *NotificationContent) (string, string) {
	title := content.Title
	message := content.Message

	if title == "" {
		title = "EDR Security Alert"
	}
	if message == "" {
		message = "Security event detected"
	}

	if content.ThreatInfo != nil {
		title = fmt.Sprintf("EDR: %s", content.ThreatInfo.ThreatName)
		message = fmt.Sprintf("File: %s\nSeverity: %d",
			content.ThreatInfo.FilePath, content.Severity)
	}

	// Truncate for native APIs
	if len(title) > 60 {
		title = title[:60] + "..."
	}
	if len(message) > 200 {
		message = message[:200] + "..."
	}

	return title, message
}

func (nns *NativeNotificationSystem) showConsoleAlert(title, message string, severity int) {
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
	os.Stdout.Sync()
}
