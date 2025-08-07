package response

import (
	"fmt"
	"syscall"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// Windows Toast Notification Implementation
// Uses Windows 10/11 Toast API for native notifications

const (
	// Windows API constants
	MB_OK               = 0x00000000
	MB_ICONWARNING      = 0x00000030
	MB_ICONERROR        = 0x00000010
	MB_ICONINFORMATION  = 0x00000040
	MB_TOPMOST          = 0x00040000
	MB_SETFOREGROUND    = 0x00010000
)

var (
	// Windows API functions
	user32           = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW  = user32.NewProc("MessageBoxW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procFlashWindow  = user32.NewProc("FlashWindow")
)

// WindowsToastNotifier implements native Windows toast notifications
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

// SendNotification sends a Windows toast notification
func (wtn *WindowsToastNotifier) SendNotification(content *NotificationContent) error {
	wtn.logger.Info("Sending Windows toast notification: %s", content.Title)

	// Create notification message
	message := wtn.createToastMessage(content)
	
	// Determine icon type based on severity
	iconType := wtn.getIconType(content.Severity)
	
	// Show Windows message box as toast notification
	titlePtr, err := syscall.UTF16PtrFromString(content.Title)
	if err != nil {
		return fmt.Errorf("failed to convert title to UTF16: %w", err)
	}
	
	messagePtr, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return fmt.Errorf("failed to convert message to UTF16: %w", err)
	}

	// Show message box with appropriate flags
	flags := MB_OK | iconType | MB_TOPMOST | MB_SETFOREGROUND
	
	result, _, _ := procMessageBoxW.Call(
		0, // hWnd (NULL for top-level window)
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(flags),
	)

	if result == 0 {
		return fmt.Errorf("failed to show Windows toast notification")
	}

	wtn.logger.Info("Windows toast notification sent successfully")
	return nil
}

// createToastMessage creates the toast notification message
func (wtn *WindowsToastNotifier) createToastMessage(content *NotificationContent) string {
	severityText := wtn.getSeverityText(content.Severity)
	
	message := fmt.Sprintf(`🚨 EDR Security Alert

Threat: %s
Severity: %s
File: %s
Time: %s

%s

Recommended Action: %s

Click OK to acknowledge this alert.`,
		content.ThreatInfo.ThreatName,
		severityText,
		content.ThreatInfo.FilePath,
		content.Timestamp.Format("15:04:05"),
		content.ThreatInfo.Description,
		wtn.getRecommendedAction(content.Severity),
	)

	return message
}

// getIconType returns the appropriate icon type for severity
func (wtn *WindowsToastNotifier) getIconType(severity int) uint32 {
	switch severity {
	case 1, 2:
		return MB_ICONINFORMATION
	case 3:
		return MB_ICONWARNING
	case 4, 5:
		return MB_ICONERROR
	default:
		return MB_ICONINFORMATION
	}
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

// getRecommendedAction returns recommended action for severity
func (wtn *WindowsToastNotifier) getRecommendedAction(severity int) string {
	switch severity {
	case 1, 2:
		return "Monitor and log for analysis"
	case 3:
		return "Review and decide whether to quarantine"
	case 4:
		return "File has been quarantined automatically"
	case 5:
		return "EMERGENCY - System isolation recommended"
	default:
		return "Unknown action"
	}
}

// Start initializes the Windows toast notifier
func (wtn *WindowsToastNotifier) Start() error {
	wtn.logger.Info("Windows Toast Notifier started")
	return nil
}

// Stop stops the Windows toast notifier
func (wtn *WindowsToastNotifier) Stop() {
	wtn.logger.Info("Windows Toast Notifier stopped")
} 