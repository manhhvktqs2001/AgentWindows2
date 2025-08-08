package response

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// ToastNotifier quản lý toast notifications
type ToastNotifier struct {
	config   *config.ResponseConfig
	logger   *utils.Logger
	notifier *WindowsToastNotifier
}

// NewToastNotifier tạo Toast Notifier mới
func NewToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *ToastNotifier {
	return &ToastNotifier{
		config:   cfg,
		logger:   logger,
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
	config        *config.ResponseConfig
	logger        *utils.Logger
	toastNotifier *WindowsToastNotifier
}

// NewSystemTrayNotifier tạo System Tray Notifier mới
func NewSystemTrayNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *SystemTrayNotifier {
	return &SystemTrayNotifier{
		config:        cfg,
		logger:        logger,
		toastNotifier: NewWindowsToastNotifier(cfg, logger),
	}
}

// Start khởi động System Tray Notifier
func (stn *SystemTrayNotifier) Start() error {
	stn.logger.Info("System Tray Notifier started")
	return stn.toastNotifier.Start()
}

// Stop dừng System Tray Notifier
func (stn *SystemTrayNotifier) Stop() {
	stn.logger.Info("System Tray Notifier stopped")
	stn.toastNotifier.Stop()
}

// SendNotification gửi system tray notification
func (stn *SystemTrayNotifier) SendNotification(content *NotificationContent) error {
	stn.logger.Info("Sending system tray notification: %s", content.Title)

	// Use the Windows toast notifier to display the notification
	// This will show a non-blocking message box
	return stn.toastNotifier.SendNotification(content)
}

// DesktopAlertNotifier quản lý desktop alert notifications
type DesktopAlertNotifier struct {
	config        *config.ResponseConfig
	logger        *utils.Logger
	toastNotifier *WindowsToastNotifier
}

// NewDesktopAlertNotifier tạo Desktop Alert Notifier mới
func NewDesktopAlertNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *DesktopAlertNotifier {
	return &DesktopAlertNotifier{
		config:        cfg,
		logger:        logger,
		toastNotifier: NewWindowsToastNotifier(cfg, logger),
	}
}

// Start khởi động Desktop Alert Notifier
func (dan *DesktopAlertNotifier) Start() error {
	dan.logger.Info("Desktop Alert Notifier started")
	return dan.toastNotifier.Start()
}

// Stop dừng Desktop Alert Notifier
func (dan *DesktopAlertNotifier) Stop() {
	dan.logger.Info("Desktop Alert Notifier stopped")
	dan.toastNotifier.Stop()
}

// SendNotification gửi desktop alert notification
func (dan *DesktopAlertNotifier) SendNotification(content *NotificationContent) error {
	dan.logger.Info("Sending desktop alert notification: %s", content.Title)

	// Use the Windows toast notifier to display the alert
	// This will show a blocking message box that requires user interaction
	return dan.toastNotifier.SendNotification(content)
}
