package response

import (
	"fmt"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// NotificationController quản lý thông báo cho người dùng
type NotificationController struct {
	config *config.ResponseConfig
	logger *utils.Logger

	// Notification channels
	toastNotifier        *ToastNotifier
	systemTrayNotifier   *SystemTrayNotifier
	desktopAlertNotifier *DesktopAlertNotifier

	// State
	notificationCount int
	lastNotification  time.Time
}

// NewNotificationController tạo Notification Controller mới
func NewNotificationController(cfg *config.ResponseConfig, logger *utils.Logger) *NotificationController {
	nc := &NotificationController{
		config: cfg,
		logger: logger,
	}

	// Initialize notification components
	nc.toastNotifier = NewToastNotifier(cfg, logger)
	nc.systemTrayNotifier = NewSystemTrayNotifier(cfg, logger)
	nc.desktopAlertNotifier = NewDesktopAlertNotifier(cfg, logger)

	return nc
}

// SendNotification gửi thông báo cho người dùng
func (nc *NotificationController) SendNotification(threat *models.ThreatInfo, severity int) error {
	nc.logger.Info("Sending notification for threat: %s (Severity: %d)", threat.ThreatName, severity)

	// Check notification thresholds
	if !nc.shouldSendNotification(severity) {
		nc.logger.Debug("Notification suppressed due to threshold settings")
		return nil
	}

	// Create notification content
	content := nc.createNotificationContent(threat, severity)

	// Send notification based on severity
	switch severity {
	case 1, 2: // Low - No user notification
		nc.logger.Debug("Low severity threat - no user notification")
		return nil

	case 3: // Medium - Toast notification
		return nc.toastNotifier.SendNotification(content)

	case 4: // High - Toast + System tray
		err1 := nc.toastNotifier.SendNotification(content)
		err2 := nc.systemTrayNotifier.SendNotification(content)
		if err1 != nil && err2 != nil {
			return fmt.Errorf("failed to send high severity notifications: %v, %v", err1, err2)
		}
		return nil

	case 5: // Critical - Desktop alert (blocking)
		return nc.desktopAlertNotifier.SendNotification(content)

	default:
		return fmt.Errorf("unknown severity level: %d", severity)
	}
}

// shouldSendNotification kiểm tra có nên gửi thông báo không
func (nc *NotificationController) shouldSendNotification(severity int) bool {
	// Check severity threshold
	if severity < nc.config.SeverityThresholds.ShowUserAlerts {
		return false
	}

	// Check notification frequency
	if time.Since(nc.lastNotification) < time.Duration(nc.config.NotificationSettings.TimeoutSeconds)*time.Second {
		return false
	}

	// Check quiet hours
	if nc.isInQuietHours() {
		nc.logger.Debug("Suppressing notification during quiet hours")
		return false
	}

	return true
}

// isInQuietHours kiểm tra có đang trong giờ yên lặng không
func (nc *NotificationController) isInQuietHours() bool {
	now := time.Now()
	hour := now.Hour()

	// Default quiet hours: 22:00 - 08:00
	quietStart := 22
	quietEnd := 8

	if hour >= quietStart || hour < quietEnd {
		return true
	}

	return false
}

// createNotificationContent tạo nội dung thông báo
func (nc *NotificationController) createNotificationContent(threat *models.ThreatInfo, severity int) *NotificationContent {
	content := &NotificationContent{
		Title:         fmt.Sprintf("EDR Security Alert - %s", threat.ThreatName),
		Message:       nc.createAlertMessage(threat, severity),
		Severity:      severity,
		SeverityText:  nc.getSeverityText(severity),
		SeverityColor: nc.getSeverityColor(severity),
		ThreatInfo:    threat,
		Timestamp:     time.Now(),
		Actions:       nc.getAvailableActions(severity),
	}

	return content
}

// createAlertMessage tạo nội dung thông báo
func (nc *NotificationController) createAlertMessage(threat *models.ThreatInfo, severity int) string {
	severityText := nc.getSeverityText(severity)

	message := fmt.Sprintf(`
🚨 Security Threat Detected

Threat: %s
Severity: %s
File: %s
Time: %s

%s

Recommended Action: %s
`,
		threat.ThreatName,
		severityText,
		threat.FilePath,
		time.Now().Format("15:04:05"),
		threat.Description,
		nc.getRecommendedAction(severity),
	)

	return message
}

// getSeverityText trả về text cho severity level
func (nc *NotificationController) getSeverityText(severity int) string {
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

// getSeverityColor trả về màu sắc cho severity
func (nc *NotificationController) getSeverityColor(severity int) string {
	switch severity {
	case 1, 2:
		return "yellow"
	case 3:
		return "orange"
	case 4:
		return "red"
	case 5:
		return "darkred"
	default:
		return "gray"
	}
}

// getRecommendedAction trả về hành động được khuyến nghị
func (nc *NotificationController) getRecommendedAction(severity int) string {
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

// getAvailableActions trả về các hành động có sẵn
func (nc *NotificationController) getAvailableActions(severity int) []NotificationAction {
	var actions []NotificationAction

	switch severity {
	case 3: // Medium - User choice
		actions = []NotificationAction{
			{ID: "quarantine", Text: "Quarantine File", Type: "primary"},
			{ID: "allow_once", Text: "Allow Once", Type: "secondary"},
			{ID: "view_details", Text: "View Details", Type: "info"},
		}

	case 4: // High - Auto-quarantined
		actions = []NotificationAction{
			{ID: "view_details", Text: "View Details", Type: "info"},
			{ID: "restore", Text: "Restore File", Type: "warning"},
			{ID: "contact_it", Text: "Contact IT", Type: "secondary"},
		}

	case 5: // Critical - Emergency
		actions = []NotificationAction{
			{ID: "acknowledge", Text: "I Understand", Type: "critical"},
			{ID: "contact_it", Text: "Contact IT Immediately", Type: "emergency"},
			{ID: "view_details", Text: "View Full Report", Type: "info"},
		}
	}

	return actions
}

// NotificationContent định nghĩa nội dung thông báo
type NotificationContent struct {
	Title         string               `json:"title"`
	Message       string               `json:"message"`
	Severity      int                  `json:"severity"`
	SeverityText  string               `json:"severity_text"`
	SeverityColor string               `json:"severity_color"`
	ThreatInfo    *models.ThreatInfo   `json:"threat_info"`
	Timestamp     time.Time            `json:"timestamp"`
	Actions       []NotificationAction `json:"actions"`
}

// NotificationAction định nghĩa hành động trong thông báo
type NotificationAction struct {
	ID   string `json:"id"`
	Text string `json:"text"`
	Type string `json:"type"` // primary, secondary, info, warning, critical, emergency
}

// Start khởi động Notification Controller
func (nc *NotificationController) Start() error {
	nc.logger.Info("Starting Notification Controller...")

	// Start notification components
	if err := nc.toastNotifier.Start(); err != nil {
		return fmt.Errorf("failed to start toast notifier: %w", err)
	}

	if err := nc.systemTrayNotifier.Start(); err != nil {
		return fmt.Errorf("failed to start system tray notifier: %w", err)
	}

	if err := nc.desktopAlertNotifier.Start(); err != nil {
		return fmt.Errorf("failed to start desktop alert notifier: %w", err)
	}

	nc.logger.Info("Notification Controller started successfully")
	return nil
}

// Stop dừng Notification Controller
func (nc *NotificationController) Stop() {
	nc.logger.Info("Stopping Notification Controller...")

	nc.toastNotifier.Stop()
	nc.systemTrayNotifier.Stop()
	nc.desktopAlertNotifier.Stop()

	nc.logger.Info("Notification Controller stopped")
}

// GetNotificationStats trả về thống kê thông báo
func (nc *NotificationController) GetNotificationStats() map[string]interface{} {
	return map[string]interface{}{
		"total_notifications":   nc.notificationCount,
		"last_notification":     nc.lastNotification,
		"toast_enabled":         nc.config.NotificationSettings.ToastEnabled,
		"system_tray_enabled":   nc.config.NotificationSettings.SystemTrayEnabled,
		"desktop_alert_enabled": nc.config.NotificationSettings.DesktopAlertEnabled,
	}
}
