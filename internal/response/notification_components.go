package response

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
	"fmt"
	"sync"
	"time"

	"edr-agent-windows/internal/models"
)

// NotificationController manages all notification types with single instances
type NotificationController struct {
	config        *config.ResponseConfig
	logger        *utils.Logger
	toastNotifier *WindowsToastNotifier
	mu            sync.RWMutex
	isStarted     bool
}

// NewNotificationController creates a new notification controller
func NewNotificationController(cfg *config.ResponseConfig, logger *utils.Logger) *NotificationController {
	return &NotificationController{
		config: cfg,
		logger: logger,
	}
}

// Start initializes all notification systems
func (nc *NotificationController) Start() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.isStarted {
		return nil
	}

	nc.logger.Info("🚀 Starting Notification Controller...")

	// Initialize Windows Toast Notifier (single instance)
	nc.toastNotifier = NewWindowsToastNotifier(nc.config, nc.logger)
	if err := nc.toastNotifier.Start(); err != nil {
		nc.logger.Warn("Failed to start Windows Toast Notifier: %v", err)
	}

	nc.isStarted = true
	nc.logger.Info("✅ Notification Controller started successfully")
	return nil
}

// Stop shuts down all notification systems
func (nc *NotificationController) Stop() {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if !nc.isStarted {
		return
	}

	nc.logger.Info("🛑 Stopping Notification Controller...")

	if nc.toastNotifier != nil {
		nc.toastNotifier.Stop()
	}

	nc.isStarted = false
	nc.logger.Info("✅ Notification Controller stopped")
}

// SendNotification sends a notification through all available channels
func (nc *NotificationController) SendNotification(threat *models.ThreatInfo, severity int) error {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	if !nc.isStarted {
		nc.logger.Warn("Notification Controller not started, skipping notification")
		return fmt.Errorf("notification controller not started")
	}

	// Create notification content
	content := &NotificationContent{
		Title:      fmt.Sprintf("EDR Security Alert - %s", threat.ThreatName),
		Message:    threat.Description,
		Severity:   severity,
		Timestamp:  time.Now(),
		ThreatInfo: threat,
	}

	// Send through Windows Toast Notifier (reuse existing instance)
	if nc.toastNotifier != nil {
		if err := nc.toastNotifier.SendNotification(content); err != nil {
			nc.logger.Warn("Windows Toast notification failed: %v", err)
		} else {
			nc.logger.Debug("✅ Windows Toast notification sent successfully")
		}
	}

	return nil
}

// NotificationContent defines the content of a notification
type NotificationContent struct {
	Title      string             `json:"title"`
	Message    string             `json:"message"`
	Severity   int                `json:"severity"`
	Timestamp  time.Time          `json:"timestamp"`
	ThreatInfo *models.ThreatInfo `json:"threat_info"`
}
