package response

import (
	"fmt"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// Modern Windows 10/11 Toast Notification System (skeleton)
type ModernToastNotifier struct {
	config       *config.ResponseConfig
	logger       *utils.Logger
	appID        string
	isRegistered bool
}

func NewModernToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *ModernToastNotifier {
	return &ModernToastNotifier{
		config: cfg,
		logger: logger,
		appID:  "EDRAgent.SecurityAlert",
	}
}

func (mtn *ModernToastNotifier) Start() error {
	mtn.logger.Info("🚀 Starting Modern Toast Notifier...")
	if err := mtn.registerApp(); err != nil {
		mtn.logger.Warn("Failed to register for modern toasts, using fallback: %v", err)
		return nil
	}
	mtn.isRegistered = true
	mtn.logger.Info("✅ Modern toast notifications registered")
	return nil
}

func (mtn *ModernToastNotifier) Stop() {
	mtn.logger.Info("🛑 Modern Toast Notifier stopped")
}

func (mtn *ModernToastNotifier) SendNotification(content *NotificationContent) error {
	if mtn.isRegistered {
		if err := mtn.showModernToast(content); err == nil {
			return nil
		}
		mtn.logger.Warn("Modern toast failed, using fallback")
	}
	// Fallback to existing system tray/balloon path
	return mtn.showSystemTrayNotification(content)
}

func (mtn *ModernToastNotifier) registerApp() error {
	// Not implemented in this skeleton; rely on fallback
	return fmt.Errorf("modern toast registration not implemented")
}

func (mtn *ModernToastNotifier) showModernToast(content *NotificationContent) error {
	// Not implemented in this skeleton; rely on fallback
	return fmt.Errorf("modern toast not implemented")
}

func (mtn *ModernToastNotifier) showSystemTrayNotification(content *NotificationContent) error {
	notifier := NewWindowsToastNotifier(mtn.config, mtn.logger)
	return notifier.SendNotification(content)
}

// PowerShell-based Toast Notifier (alternative; skeleton execution)
type PowerShellToastNotifier struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

func NewPowerShellToastNotifier(cfg *config.ResponseConfig, logger *utils.Logger) *PowerShellToastNotifier {
	return &PowerShellToastNotifier{config: cfg, logger: logger}
}

func (ptn *PowerShellToastNotifier) Start() error {
	ptn.logger.Info("🚀 Starting PowerShell Toast Notifier...")
	return nil
}

func (ptn *PowerShellToastNotifier) Stop() {
	ptn.logger.Info("🛑 PowerShell Toast Notifier stopped")
}

func (ptn *PowerShellToastNotifier) SendNotification(content *NotificationContent) error {
	// For now, delegate to WindowsToastNotifier which already manages PowerShell scripts internally
	notifier := NewWindowsToastNotifier(ptn.config, ptn.logger)
	return notifier.SendNotification(content)
}

// Unified Notification Manager that tries multiple methods
type UnifiedNotificationManager struct {
	config    *config.ResponseConfig
	logger    *utils.Logger
	notifiers []NotificationProvider
	fallback  *WindowsToastNotifier
}

type NotificationProvider interface {
	Start() error
	Stop()
	SendNotification(content *NotificationContent) error
}

func NewUnifiedNotificationManager(cfg *config.ResponseConfig, logger *utils.Logger) *UnifiedNotificationManager {
	unm := &UnifiedNotificationManager{
		config:   cfg,
		logger:   logger,
		fallback: NewWindowsToastNotifier(cfg, logger),
	}
	// Preference order: Modern → PowerShell helper → fallback (balloon/WPF)
	unm.notifiers = []NotificationProvider{
		NewModernToastNotifier(cfg, logger),
		NewPowerShellToastNotifier(cfg, logger),
		unm.fallback,
	}
	return unm
}

func (unm *UnifiedNotificationManager) Start() error {
	unm.logger.Info("🚀 Starting Unified Notification Manager...")
	for i, notifier := range unm.notifiers {
		if err := notifier.Start(); err != nil {
			unm.logger.Warn("Notifier %d failed to start: %v", i, err)
		}
	}
	// Ensure fallback is started
	if err := unm.fallback.Start(); err != nil {
		return fmt.Errorf("fallback notifier failed: %w", err)
	}
	unm.logger.Info("✅ Unified Notification Manager started")
	return nil
}

func (unm *UnifiedNotificationManager) Stop() {
	unm.logger.Info("🛑 Stopping Unified Notification Manager...")
	for _, notifier := range unm.notifiers {
		notifier.Stop()
	}
}

func (unm *UnifiedNotificationManager) SendNotification(content *NotificationContent) error {
	for i, notifier := range unm.notifiers {
		if err := notifier.SendNotification(content); err == nil {
			unm.logger.Debug("Notification sent via provider %d", i)
			return nil
		}
	}
	unm.logger.Warn("All notification providers failed, using fallback")
	return unm.fallback.SendNotification(content)
}

// Test function to demonstrate different notification styles
func TestAllNotificationTypes(cfg *config.ResponseConfig, logger *utils.Logger) {
	logger.Info("🧪 Testing all notification types...")

	testCases := []struct {
		severity int
		title    string
		message  string
	}{
		{5, "CRITICAL THREAT", "Ransomware detected! System compromised."},
		{4, "HIGH SEVERITY", "Malware found in system files."},
		{3, "MEDIUM ALERT", "Suspicious activity detected."},
		{2, "LOW PRIORITY", "Unusual network connection."},
		{1, "INFO", "System scan completed."},
	}

	manager := NewUnifiedNotificationManager(cfg, logger)
	if err := manager.Start(); err != nil {
		logger.Error("Failed to start notification manager: %v", err)
		return
	}
	defer manager.Stop()

	for i, tc := range testCases {
		content := &NotificationContent{
			Title:     tc.title,
			Message:   tc.message,
			Severity:  tc.severity,
			Timestamp: time.Now(),
			ThreatInfo: &models.ThreatInfo{
				ThreatName:  fmt.Sprintf("test_threat_%d", i+1),
				FilePath:    fmt.Sprintf("C:\\temp\\test%d.exe", i+1),
				Description: "Test threat for notification demo",
			},
		}

		logger.Info("Testing severity %d notification...", tc.severity)
		if err := manager.SendNotification(content); err != nil {
			logger.Error("Failed to send test notification: %v", err)
		}
		time.Sleep(2 * time.Second)
	}

	logger.Info("✅ Notification test completed")
}
