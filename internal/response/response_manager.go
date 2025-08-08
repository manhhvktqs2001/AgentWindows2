package response

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// ResponseManager quản lý toàn bộ hệ thống phản ứng
type ResponseManager struct {
	config            *config.ResponseConfig
	logger            *utils.Logger
	severityAssessor  *SeverityAssessor
	notificationCtrl  *NotificationController
	actionEngine      *ActionEngine
	evidenceCollector *EvidenceCollector
	serverClient      interface{}

	// State management
	activeThreats  map[string]*models.ThreatInfo
	quarantineList map[string]bool
	whitelist      map[string]bool
	mu             sync.RWMutex

	// Channels for communication
	threatChan   chan *models.ThreatInfo
	responseChan chan *ResponseAction
	stopChan     chan bool
}

// ResponseAction định nghĩa hành động phản ứng
type ResponseAction struct {
	ThreatInfo   *models.ThreatInfo
	ActionType   string // quarantine, block, alert, etc.
	Severity     int
	UserNotified bool
	AutoExecuted bool
	Timestamp    time.Time
	Evidence     map[string]interface{}
}

// NewResponseManager tạo Response Manager mới
func NewResponseManager(cfg *config.ResponseConfig, logger *utils.Logger, serverClient interface{}) *ResponseManager {
	rm := &ResponseManager{
		config:         cfg,
		logger:         logger,
		serverClient:   serverClient,
		activeThreats:  make(map[string]*models.ThreatInfo),
		quarantineList: make(map[string]bool),
		whitelist:      make(map[string]bool),
		threatChan:     make(chan *models.ThreatInfo, 100),
		responseChan:   make(chan *ResponseAction, 100),
		stopChan:       make(chan bool),
	}

	// Initialize components
	rm.severityAssessor = NewSeverityAssessor(cfg, logger)
	rm.notificationCtrl = NewNotificationController(cfg, logger)
	rm.actionEngine = NewActionEngine(cfg, logger)
	rm.evidenceCollector = NewEvidenceCollector(cfg, logger)

	return rm
}

// Start khởi động Response Manager
func (rm *ResponseManager) Start() error {
	rm.logger.Info("Starting Response Manager...")

	// Start background workers
	go rm.threatProcessor()
	go rm.responseProcessor()
	go rm.cleanupWorker()

	rm.logger.Info("Response Manager started successfully")
	return nil
}

// Stop dừng Response Manager
func (rm *ResponseManager) Stop() {
	rm.logger.Info("Stopping Response Manager...")
	close(rm.stopChan)
	rm.logger.Info("Response Manager stopped")
}

// HandleThreat xử lý threat được phát hiện
func (rm *ResponseManager) HandleThreat(threat *models.ThreatInfo) error {
	rm.logger.Info("Handling threat: %s (Severity: %d)", threat.ThreatName, threat.Severity)

	// Add to active threats
	rm.mu.Lock()
	rm.activeThreats[threat.FilePath] = threat
	rm.mu.Unlock()

	// Send to threat processor
	select {
	case rm.threatChan <- threat:
		return nil
	default:
		return fmt.Errorf("threat channel full")
	}
}

// threatProcessor xử lý threats trong background
func (rm *ResponseManager) threatProcessor() {
	for {
		select {
		case <-rm.stopChan:
			return
		case threat := <-rm.threatChan:
			rm.processThreat(threat)
		}
	}
}

// processThreat xử lý một threat cụ thể
func (rm *ResponseManager) processThreat(threat *models.ThreatInfo) {
	startTime := time.Now()
	rm.logger.Info("Processing threat: %s", threat.ThreatName)

	// Step 1: Assess severity
	severity := rm.severityAssessor.AssessSeverity(threat)
	threat.Severity = severity

	// Step 2: Check whitelist
	if rm.isWhitelisted(threat.FilePath) {
		rm.logger.Info("Threat whitelisted: %s", threat.FilePath)
		return
	}

	// Step 3: Determine response based on severity
	response := rm.determineResponse(threat)

	// Step 4: Execute automated actions
	if response.AutoExecuted {
		rm.executeAutomatedActions(threat, response)
	}

	// Step 5: Collect evidence
	evidence := rm.evidenceCollector.CollectEvidence(threat)

	// Step 6: Send to response processor
	response.Evidence = evidence
	select {
	case rm.responseChan <- response:
	default:
		rm.logger.Warn("Response channel full, dropping response")
	}

	// Step 7: Send to server (disabled to avoid duplicate alerts)
	// rm.sendToServer(threat, response)

	processingTime := time.Since(startTime)
	rm.logger.Info("Threat processed in %v: %s (Severity: %d)", processingTime, threat.ThreatName, severity)
}

// determineResponse xác định phản ứng dựa trên severity
func (rm *ResponseManager) determineResponse(threat *models.ThreatInfo) *ResponseAction {
	response := &ResponseAction{
		ThreatInfo: threat,
		Severity:   threat.Severity,
		Timestamp:  time.Now(),
	}

	switch threat.Severity {
	case 1, 2: // Low
		response.ActionType = "log_only"
		response.UserNotified = false
		response.AutoExecuted = false

	case 3: // Medium
		response.ActionType = "alert_user"
		response.UserNotified = true
		response.AutoExecuted = false

	case 4: // High
		response.ActionType = "auto_quarantine"
		response.UserNotified = true
		response.AutoExecuted = true

	case 5: // Critical
		response.ActionType = "emergency_response"
		response.UserNotified = true
		response.AutoExecuted = true
	}

	return response
}

// executeAutomatedActions thực hiện hành động tự động
func (rm *ResponseManager) executeAutomatedActions(threat *models.ThreatInfo, response *ResponseAction) {
	rm.logger.Info("Executing automated actions for threat: %s", threat.ThreatName)

	// Quarantine file if needed
	if response.Severity >= 4 {
		err := rm.actionEngine.QuarantineFile(threat.FilePath)
		if err != nil {
			rm.logger.Error("Failed to quarantine file: %v", err)
		}
	}

	// Terminate processes if critical
	if response.Severity == 5 {
		err := rm.actionEngine.TerminateProcesses(threat.ProcessID)
		if err != nil {
			rm.logger.Error("Failed to terminate processes: %v", err)
		}
	}

	// Block network if critical
	if response.Severity == 5 {
		err := rm.actionEngine.BlockNetworkConnections(threat.ProcessID)
		if err != nil {
			rm.logger.Error("Failed to block network connections: %v", err)
		}
	}
}

// responseProcessor xử lý responses trong background
func (rm *ResponseManager) responseProcessor() {
	for {
		select {
		case <-rm.stopChan:
			return
		case response := <-rm.responseChan:
			rm.processResponse(response)
		}
	}
}

// processResponse xử lý một response cụ thể
func (rm *ResponseManager) processResponse(response *ResponseAction) {
	rm.logger.Info("Processing response: %s for threat: %s", response.ActionType, response.ThreatInfo.ThreatName)

	// Send notification to user if needed
	if response.UserNotified {
		err := rm.notificationCtrl.SendNotification(response.ThreatInfo, response.Severity)
		if err != nil {
			rm.logger.Error("Failed to send notification: %v", err)
		}
	}

	// Log response action
	rm.logger.Info("Response completed: %s (Severity: %d)", response.ActionType, response.Severity)
}

// isWhitelisted kiểm tra file có trong whitelist không
func (rm *ResponseManager) isWhitelisted(filePath string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.whitelist[filePath]
}

// AddToWhitelist thêm file vào whitelist
func (rm *ResponseManager) AddToWhitelist(filePath string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.whitelist[filePath] = true
	rm.logger.Info("Added to whitelist: %s", filePath)
}

// RemoveFromWhitelist xóa file khỏi whitelist
func (rm *ResponseManager) RemoveFromWhitelist(filePath string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.whitelist, filePath)
	rm.logger.Info("Removed from whitelist: %s", filePath)
}

// sendToServer gửi thông tin threat về server
func (rm *ResponseManager) sendToServer(threat *models.ThreatInfo, response *ResponseAction) {
	if rm.serverClient == nil {
		return
	}

	// Create alert data
	alertData := map[string]interface{}{
		"rule_name":      threat.ThreatName, // Sử dụng ThreatName làm rule_name
		"title":          fmt.Sprintf("EDR Security Alert - %s", threat.ThreatName),
		"description":    threat.Description,
		"file_path":      threat.FilePath,
		"file_name":      filepath.Base(threat.FilePath),
		"severity":       threat.Severity,
		"action_type":    response.ActionType,
		"auto_executed":  response.AutoExecuted,
		"detection_time": response.Timestamp.Format(time.RFC3339),
		"status":         "new",
		"event_type":     "threat_detection",
		"timestamp":      response.Timestamp,
		"evidence":       response.Evidence,
	}

	// Send to server
	if sendAlert, ok := rm.serverClient.(interface {
		SendAlert(data map[string]interface{}) error
	}); ok {
		err := sendAlert.SendAlert(alertData)
		if err != nil {
			rm.logger.Error("Failed to send alert to server: %v", err)
		}
	}
}

// cleanupWorker dọn dẹp dữ liệu cũ
func (rm *ResponseManager) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-rm.stopChan:
			return
		case <-ticker.C:
			rm.cleanup()
		}
	}
}

// cleanup dọn dẹp dữ liệu cũ
func (rm *ResponseManager) cleanup() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Remove old threats (older than 24 hours)
	cutoff := time.Now().Add(-24 * time.Hour)
	for filePath, threat := range rm.activeThreats {
		if threat.Timestamp.Before(cutoff) {
			delete(rm.activeThreats, filePath)
		}
	}

	rm.logger.Debug("Cleanup completed")
}

// GetActiveThreats trả về danh sách threats đang hoạt động
func (rm *ResponseManager) GetActiveThreats() []*models.ThreatInfo {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	threats := make([]*models.ThreatInfo, 0, len(rm.activeThreats))
	for _, threat := range rm.activeThreats {
		threats = append(threats, threat)
	}
	return threats
}

// GetQuarantineList trả về danh sách file đã quarantine
func (rm *ResponseManager) GetQuarantineList() map[string]bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[string]bool)
	for k, v := range rm.quarantineList {
		result[k] = v
	}
	return result
}
