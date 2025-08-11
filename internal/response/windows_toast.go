package response

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"

	"golang.org/x/sys/windows"
)

// WindowsToastNotifier shows bottom-right system tray balloon notifications
type WindowsToastNotifier struct {
	config  *config.ResponseConfig
	logger  *utils.Logger
	mu      sync.Mutex
	nid     NOTIFYICONDATA
	hasIcon bool
}

// NOTIFYICONDATA maps to Shell_NotifyIconW data
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

const (
	NIM_ADD    = 0x00000000
	NIM_MODIFY = 0x00000001
	NIM_DELETE = 0x00000002

	NIF_ICON = 0x00000002
	NIF_TIP  = 0x00000004
	NIF_INFO = 0x00000010

	NIIF_INFO    = 0x00000001
	NIIF_WARNING = 0x00000002
	NIIF_ERROR   = 0x00000003

	IDI_APPLICATION = 32512
	IDI_WARNING     = 32515
	IDI_ERROR       = 32513
	IDI_INFORMATION = 32516
)

var (
	shell32              = windows.NewLazySystemDLL("shell32.dll")
	user32               = windows.NewLazySystemDLL("user32.dll")
	procShellNotifyIconW = shell32.NewProc("Shell_NotifyIconW")
	procLoadIconW        = user32.NewProc("LoadIconW")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
)

func NewWindowsToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsToastNotifier {
	return &WindowsToastNotifier{config: cfg, logger: logger}
}

func (wtn *WindowsToastNotifier) Start() error {
	wtn.logger.Info("🚀 Starting Windows Toast Notifier...")
	wtn.mu.Lock()
	defer wtn.mu.Unlock()

	if wtn.hasIcon {
		return nil
	}

<<<<<<< HEAD
	// Try to initialize persistent tray icon, but don't fail if it doesn't work
=======
	// Initialize persistent tray icon (no balloon yet)
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	wtn.nid = NOTIFYICONDATA{}
	wtn.nid.CbSize = uint32(unsafe.Sizeof(wtn.nid))
	wtn.nid.UID = 1
	wtn.nid.UFlags = NIF_ICON | NIF_TIP

	// Default icon
	hIcon, _, _ := procLoadIconW.Call(0, uintptr(IDI_APPLICATION))
	wtn.nid.HIcon = windows.Handle(hIcon)

	tipUTF16, _ := windows.UTF16FromString("EDR Agent")
	copy(wtn.nid.SzTip[:], tipUTF16)

	ret, _, _ := procShellNotifyIconW.Call(NIM_ADD, uintptr(unsafe.Pointer(&wtn.nid)))
	if ret == 0 {
<<<<<<< HEAD
		// Don't fail - just log and continue without tray icon
		wtn.logger.Debug("Tray icon not available, continuing without system tray")
		wtn.hasIcon = false
		return nil
	}
	wtn.hasIcon = true
	wtn.logger.Info("✅ Windows Toast Notifier started with tray icon")
=======
		return fmt.Errorf("failed to add tray icon")
	}
	wtn.hasIcon = true
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	return nil
}

func (wtn *WindowsToastNotifier) Stop() {
	wtn.mu.Lock()
	defer wtn.mu.Unlock()
	if wtn.hasIcon {
		procShellNotifyIconW.Call(NIM_DELETE, uintptr(unsafe.Pointer(&wtn.nid)))
		wtn.hasIcon = false
	}
	wtn.logger.Info("🛑 Windows Toast Notifier stopped")
}

func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	wtn.showConsoleAlert(content)
	if err := wtn.showSystemTrayNotification(content); err != nil {
		wtn.logger.Warn("System tray notification failed: %v", err)
		if content.Severity >= 4 {
			return wtn.showMessageBoxAlert(content)
		}
	}
	return nil
}

func (wtn *WindowsToastNotifier) showSystemTrayNotification(content *NotificationContent) error {
	wtn.mu.Lock()
	defer wtn.mu.Unlock()

<<<<<<< HEAD
	// If no tray icon, fall back to message box
	if !wtn.hasIcon {
		wtn.logger.Debug("No tray icon available, using message box fallback")
		return wtn.showMessageBoxAlert(content)
=======
	// Ensure persistent icon exists
	if !wtn.hasIcon {
		if err := wtn.Start(); err != nil {
			return err
		}
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	}

	// Update icon based on severity
	iconID := wtn.getIconForSeverity(content.Severity)
	hIcon, _, _ := procLoadIconW.Call(0, uintptr(iconID))
	wtn.nid.HIcon = windows.Handle(hIcon)

	title := wtn.prepareTitle(content)
	message := wtn.prepareMessage(content)

	titleUTF16, _ := windows.UTF16FromString(title)
	messageUTF16, _ := windows.UTF16FromString(message)

	// Set flags to modify balloon info
	wtn.nid.UFlags = NIF_INFO | NIF_ICON | NIF_TIP
	copy(wtn.nid.SzInfoTitle[:], titleUTF16)
	copy(wtn.nid.SzInfo[:], messageUTF16)
	wtn.nid.DwInfoFlags = wtn.getNotificationFlags(content.Severity)
	wtn.nid.UTimeout = 3000 // ~3 seconds

	// Show balloon by modifying existing icon
	ret, _, _ := procShellNotifyIconW.Call(NIM_MODIFY, uintptr(unsafe.Pointer(&wtn.nid)))
	if ret == 0 {
<<<<<<< HEAD
		wtn.logger.Debug("System tray notification failed, using message box fallback")
		return wtn.showMessageBoxAlert(content)
=======
		return fmt.Errorf("failed to show system tray notification")
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	}

	wtn.logger.Info("✅ System tray notification displayed: %s", title)
	return nil
}

func (wtn *WindowsToastNotifier) showMessageBoxAlert(content *NotificationContent) error {
	title := wtn.prepareTitle(content)
	message := wtn.prepareMessage(content)
	mbType := uint32(0x00000040) // MB_ICONINFORMATION
	switch {
	case content.Severity >= 5:
		mbType = 0x00000010 // MB_ICONERROR
	case content.Severity >= 4:
		mbType = 0x00000030 // MB_ICONWARNING
	}
	mbType |= 0x00010000 // MB_SETFOREGROUND
	mbType |= 0x00040000 // MB_TOPMOST

	titlePtr, _ := windows.UTF16PtrFromString(title)
	messagePtr, _ := windows.UTF16PtrFromString(message)
	go func() {
		procMessageBoxW.Call(0, uintptr(unsafe.Pointer(messagePtr)), uintptr(unsafe.Pointer(titlePtr)), uintptr(mbType))
	}()
	return nil
}

func (wtn *WindowsToastNotifier) showConsoleAlert(content *NotificationContent) {
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
	_ = os.Stdout.Sync()
	if content.Severity >= 4 {
		wtn.playSystemBeep(content.Severity)
	}
}

func (wtn *WindowsToastNotifier) playSystemBeep(severity int) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	beep := kernel32.NewProc("Beep")
	patterns := map[int][]struct{ freq, duration int }{
		5: {{1000, 300}, {800, 300}, {1000, 300}},
		4: {{800, 400}, {600, 400}},
		3: {{600, 500}},
	}
	if pattern, ok := patterns[severity]; ok {
		go func() {
			for i, p := range pattern {
				beep.Call(uintptr(p.freq), uintptr(p.duration))
				if i < len(pattern)-1 {
					time.Sleep(150 * time.Millisecond)
				}
			}
		}()
	}
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
	if content.ThreatInfo != nil {
		fileLine := ""
		if content.ThreatInfo.FilePath != "" {
			fileLine = fmt.Sprintf("\nFile: %s", content.ThreatInfo.FilePath)
		}
		return fmt.Sprintf("Threat detected: %s%s\nSeverity: %d\nTime: %s", content.ThreatInfo.ThreatName, fileLine, content.Severity, content.Timestamp.Format("15:04:05"))
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
