package response

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// ToastNotifier quản lý toast notifications
type ToastNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
	notifier *WindowsToastNotifier
}

// NewToastNotifier tạo Toast Notifier mới
func NewToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *ToastNotifier {
	return &ToastNotifier{
		config: cfg,
		logger: logger,
		notifier: NewWindowsToastNotifier(cfg, logger),
	}
}

// Start khởi động Toast Notifier
func (tn *ToastNotifier) Start() error {
	tn.logger.Info("Toast Notifier started")
	return tn.notifier.Start()
}

// Stop dừng Toast Notifier
func (tn *ToastNotifier) Stop() {
	tn.logger.Info("Toast Notifier stopped")
	tn.notifier.Stop()
}

// SendNotification gửi toast notification
func (tn *ToastNotifier) SendNotification(content *NotificationContent) error {
	tn.logger.Info("Sending toast notification: %s", content.Title)
	return tn.notifier.SendNotification(content)
}

// SystemTrayNotifier quản lý system tray notifications
type SystemTrayNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewSystemTrayNotifier tạo System Tray Notifier mới
func NewSystemTrayNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *SystemTrayNotifier {
	return &SystemTrayNotifier{
		config: cfg,
		logger: logger,
	}
}

// Start khởi động System Tray Notifier
func (stn *SystemTrayNotifier) Start() error {
	stn.logger.Info("System Tray Notifier started")
	return nil
}

// Stop dừng System Tray Notifier
func (stn *SystemTrayNotifier) Stop() {
	stn.logger.Info("System Tray Notifier stopped")
}

// SendNotification gửi system tray notification
func (stn *SystemTrayNotifier) SendNotification(content *NotificationContent) error {
	stn.logger.Info("Sending system tray notification: %s", content.Title)

	// This is a simplified implementation
	// In a real system, you would use Windows System Tray API
	stn.logger.Info("System tray notification content: %s", content.Message)

	return nil
}

// DesktopAlertNotifier quản lý desktop alert notifications
type DesktopAlertNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewDesktopAlertNotifier tạo Desktop Alert Notifier mới
func NewDesktopAlertNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *DesktopAlertNotifier {
	return &DesktopAlertNotifier{
		config: cfg,
		logger: logger,
	}
}

// Start khởi động Desktop Alert Notifier
func (dan *DesktopAlertNotifier) Start() error {
	dan.logger.Info("Desktop Alert Notifier started")
	return nil
}

// Stop dừng Desktop Alert Notifier
func (dan *DesktopAlertNotifier) Stop() {
	dan.logger.Info("Desktop Alert Notifier stopped")
}

// SendNotification gửi desktop alert notification
func (dan *DesktopAlertNotifier) SendNotification(content *NotificationContent) error {
	dan.logger.Info("Sending desktop alert notification: %s", content.Title)

	// This is a simplified implementation
	// In a real system, you would use Windows Desktop Alert API
	dan.logger.Info("Desktop alert notification content: %s", content.Message)

	return nil
}
