package response

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-agent-windows/internal/communication"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type ResponseManager struct {
	config            *config.ResponseConfig
	logger            *utils.Logger
	severityAssessor  *SeverityAssessor
	notificationCtrl  *NotificationController
	actionEngine      *ActionEngine
	evidenceCollector *EvidenceCollector
	serverClient      interface{}

	// Enhanced state management
	activeThreats     map[string]*models.ThreatInfo
	quarantineList    map[string]bool
	whitelist         map[string]bool
	processedThreats  map[string]time.Time // Prevent duplicate processing
	suppressedThreats map[string]int       // Track suppression counts
	mu                sync.RWMutex

	// Channels for communication
	threatChan   chan *models.ThreatInfo
	responseChan chan *ResponseAction
	stopChan     chan bool

	// Performance metrics
	totalThreats      int64
	processedCount    int64
	suppressedCount   int64
	quarantineCount   int64
	notificationCount int64
}

type ResponseAction struct {
	ThreatInfo        *models.ThreatInfo
	ActionType        string
	Severity          int
	UserNotified      bool
	AutoExecuted      bool
	Timestamp         time.Time
	Evidence          map[string]interface{}
	Suppressed        bool
	SuppressionReason string
}

func NewResponseManager(cfg *config.ResponseConfig, logger *utils.Logger, serverClient interface{}) *ResponseManager {
	rm := &ResponseManager{
		config:            cfg,
		logger:            logger,
		serverClient:      serverClient,
		activeThreats:     make(map[string]*models.ThreatInfo),
		quarantineList:    make(map[string]bool),
		whitelist:         make(map[string]bool),
		processedThreats:  make(map[string]time.Time),
		suppressedThreats: make(map[string]int),
		threatChan:        make(chan *models.ThreatInfo, 2000), // Increased buffer
		responseChan:      make(chan *ResponseAction, 2000),    // Increased buffer
		stopChan:          make(chan bool),
	}

	// Initialize components
	rm.severityAssessor = NewSeverityAssessor(cfg, logger)
	rm.notificationCtrl = NewNotificationController(cfg, logger)

	// Convert serverClient to proper type for ActionEngine
	var serverClientTyped *communication.ServerClient
	if sc, ok := serverClient.(*communication.ServerClient); ok {
		serverClientTyped = sc
	}

	rm.actionEngine = NewActionEngine(cfg, logger, serverClientTyped)
	rm.evidenceCollector = NewEvidenceCollector(cfg, logger)

	return rm
}

// GetNotificationController returns the notification controller instance
func (rm *ResponseManager) GetNotificationController() *NotificationController {
	return rm.notificationCtrl
}

func (rm *ResponseManager) Start() error {
	rm.logger.Info("Starting Response Manager...")

	// Start background workers
	go rm.threatProcessor()
	go rm.responseProcessor()
	go rm.cleanupWorker()

	rm.logger.Info("Response Manager started successfully")
	return nil
}

func (rm *ResponseManager) Stop() {
	rm.logger.Info("Stopping Response Manager...")
	close(rm.stopChan)
	rm.logger.Info("Response Manager stopped")
}

func (rm *ResponseManager) HandleThreat(threat *models.ThreatInfo) error {
	rm.totalThreats++
	rm.logger.Debug("Handling threat: %s (Severity: %d)", threat.ThreatName, threat.Severity)

	// Quick duplicate check
	threatKey := fmt.Sprintf("%s|%s", threat.FilePath, threat.ThreatName)

	rm.mu.RLock()
	if lastProcessed, exists := rm.processedThreats[threatKey]; exists {
		if time.Since(lastProcessed) < 30*time.Second {
			rm.suppressedCount++
			rm.mu.RUnlock()
			rm.logger.Debug("Suppressing duplicate threat: %s", threatKey)
			return nil
		}
	}
	rm.mu.RUnlock()

	// Add to active threats
	rm.mu.Lock()
	rm.activeThreats[threat.FilePath] = threat
	rm.processedThreats[threatKey] = time.Now()
	rm.mu.Unlock()

	// Send to threat processor with non-blocking send
	select {
	case rm.threatChan <- threat:
		return nil
	default:
		// Channel is full, process immediately in goroutine
		rm.logger.Warn("Threat channel full, processing threat immediately: %s", threat.ThreatName)
		go rm.processThreatSafe(threat)
		return nil
	}
}

func (rm *ResponseManager) threatProcessor() {
	for {
		select {
		case <-rm.stopChan:
			return
		case threat := <-rm.threatChan:
			rm.processThreatSafe(threat)
		}
	}
}

func (rm *ResponseManager) processThreatSafe(threat *models.ThreatInfo) {
	defer func() {
		if r := recover(); r != nil {
			rm.logger.Error("Panic in threat processing: %v", r)
		}
	}()

	rm.processThreat(threat)
}

func (rm *ResponseManager) processThreat(threat *models.ThreatInfo) {
	startTime := time.Now()
	rm.processedCount++
	rm.logger.Debug("Processing threat: %s", threat.ThreatName)

	// Step 1: Enhanced severity assessment
	originalSeverity := threat.Severity
	severity := rm.severityAssessor.AssessSeverity(threat)
	threat.Severity = severity

	if severity != originalSeverity {
		rm.logger.Debug("Severity adjusted: %s from %d to %d",
			threat.ThreatName, originalSeverity, severity)
	}

	// Step 2: Check whitelist
	if rm.isWhitelisted(threat.FilePath) {
		rm.logger.Info("Threat whitelisted: %s", threat.FilePath)
		return
	}

	// Step 3: Apply intelligent suppression
	if suppressed, reason := rm.shouldSuppressThreat(threat); suppressed {
		rm.suppressedCount++
		rm.logger.Debug("Threat suppressed (%s): %s", reason, threat.ThreatName)

		// Still create a response record but mark as suppressed
		response := &ResponseAction{
			ThreatInfo:        threat,
			ActionType:        "suppressed",
			Severity:          severity,
			UserNotified:      false,
			AutoExecuted:      false,
			Timestamp:         time.Now(),
			Suppressed:        true,
			SuppressionReason: reason,
		}

		// Send to response processor for logging
		select {
		case rm.responseChan <- response:
		default:
			rm.logger.Debug("Response channel full, dropping suppressed response")
		}
		return
	}

	// Step 4: Determine response based on severity
	response := rm.determineResponse(threat)

	// Step 5: Execute automated actions for high-severity threats
	if response.AutoExecuted {
		rm.executeAutomatedActionsSafe(threat, response)
	}

	// Step 6: Handle notifications for significant threats
	if response.UserNotified && severity >= rm.config.SeverityThresholds.ShowUserAlerts {
		rm.sendNotificationSafe(threat, severity)
	}

	// Step 7: Collect evidence
	evidence := rm.evidenceCollector.CollectEvidence(threat)
	response.Evidence = evidence

	// Step 8: Send to response processor
	select {
	case rm.responseChan <- response:
	default:
		rm.logger.Warn("Response channel full, dropping response")
	}

	// Step 9: Send to server
	rm.sendToServerSafe(threat, response)

	processingTime := time.Since(startTime)
	rm.logger.Debug("Threat processed in %v: %s (Severity: %d)",
		processingTime, threat.ThreatName, severity)
}

func (rm *ResponseManager) shouldSuppressThreat(threat *models.ThreatInfo) (bool, string) {
	// Environmental detections on system paths
	if rm.isEnvironmentalDetection(threat) && rm.isSystemPath(threat.FilePath) {
		return true, "environmental_system_path"
	}

	// Very low severity threats
	if threat.Severity <= 1 {
		return true, "low_severity"
	}

	// Quarantine directory
	if strings.Contains(strings.ToLower(threat.FilePath), "quarantine") {
		return true, "quarantine_directory"
	}

	// Repeated suppression tracking
	threatKey := fmt.Sprintf("%s|%s", threat.FilePath, threat.ThreatName)
	rm.mu.RLock()
	suppressCount := rm.suppressedThreats[threatKey]
	rm.mu.RUnlock()

	if suppressCount >= 10 {
		return true, "repeated_detection"
	}

	return false, ""
}

func (rm *ResponseManager) isEnvironmentalDetection(threat *models.ThreatInfo) bool {
	return rm.severityAssessor.IsEnvironmentalRule(threat.ThreatName)
}

func (rm *ResponseManager) isSystemPath(filePath string) bool {
	if filePath == "" {
		return false
	}

	lowerPath := strings.ToLower(filePath)
	systemPaths := []string{
		"\\windows\\system32\\",
		"\\windows\\syswow64\\",
		"\\program files\\",
		"\\program files (x86)\\",
		"edgewebview",
		"microsoft\\edge",
		"windowspowershell",
	}

	for _, sysPath := range systemPaths {
		if strings.Contains(lowerPath, sysPath) {
			return true
		}
	}

	return false
}

func (rm *ResponseManager) determineResponse(threat *models.ThreatInfo) *ResponseAction {
	response := &ResponseAction{
		ThreatInfo: threat,
		Severity:   threat.Severity,
		Timestamp:  time.Now(),
	}

	switch threat.Severity {
	case 1: // Low - Environmental/Informational
		response.ActionType = "log_only"
		response.UserNotified = false
		response.AutoExecuted = false

	case 2: // Low-Medium
		response.ActionType = "log_monitor"
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

func (rm *ResponseManager) executeAutomatedActionsSafe(threat *models.ThreatInfo, response *ResponseAction) {
	defer func() {
		if r := recover(); r != nil {
			rm.logger.Error("Panic in automated actions: %v", r)
		}
	}()

	rm.executeAutomatedActions(threat, response)
}

func (rm *ResponseManager) executeAutomatedActions(threat *models.ThreatInfo, response *ResponseAction) {
	rm.logger.Info("Executing automated actions for threat: %s", threat.ThreatName)

	// Quarantine file if needed (skip environmental detections and system files)
	if response.Severity >= rm.config.SeverityThresholds.AutoQuarantine &&
		!rm.isEnvironmentalDetection(threat) &&
		!rm.isSystemPath(threat.FilePath) {

		if err := rm.actionEngine.QuarantineFile(threat.FilePath); err != nil {
			rm.logger.Error("Failed to quarantine file: %v", err)
		} else {
			rm.quarantineCount++
			rm.logger.Info("File quarantined: %s", threat.FilePath)
		}
	}

	// Terminate processes if critical and not system process
	if response.Severity >= rm.config.SeverityThresholds.BlockExecution &&
		threat.ProcessID > 0 &&
		!rm.isSystemProcess(threat.ProcessID) {

		if err := rm.actionEngine.TerminateProcesses(threat.ProcessID); err != nil {
			rm.logger.Warn("Failed to terminate process %d: %v", threat.ProcessID, err)
		}
	}

	// Block network if critical
	if response.Severity >= rm.config.SeverityThresholds.BlockExecution &&
		threat.ProcessID > 0 {

		if err := rm.actionEngine.BlockNetworkConnections(threat.ProcessID); err != nil {
			rm.logger.Warn("Failed to block network connections: %v", err)
		}
	}
}

func (rm *ResponseManager) isSystemProcess(processID int) bool {
	// Basic system PID checks
	systemProcessIDs := []int{0, 4} // System Idle and System

	for _, sysID := range systemProcessIDs {
		if processID == sysID {
			return true
		}
	}

	// Best-effort image-name based guard to avoid terminating core services
	// We avoid importing the process controller here to keep responsibilities separate.
	// Instead, depend on ActionEngine/WindowsProcessController for the final safety check.
	return false
}

func (rm *ResponseManager) sendNotificationSafe(threat *models.ThreatInfo, severity int) {
	defer func() {
		if r := recover(); r != nil {
			rm.logger.Error("Panic in notification sending: %v", r)
		}
	}()

	if rm.notificationCtrl != nil {
		rm.notificationCount++
		if err := rm.notificationCtrl.SendNotification(threat, severity); err != nil {
			rm.logger.Warn("Failed to send notification: %v", err)
		} else {
			rm.logger.Debug("✅ User notification sent successfully")
		}
	}
}

func (rm *ResponseManager) responseProcessor() {
	for {
		select {
		case <-rm.stopChan:
			return
		case response := <-rm.responseChan:
			rm.processResponseSafe(response)
		}
	}
}

func (rm *ResponseManager) processResponseSafe(response *ResponseAction) {
	defer func() {
		if r := recover(); r != nil {
			rm.logger.Error("Panic in response processing: %v", r)
		}
	}()

	rm.processResponse(response)
}

func (rm *ResponseManager) processResponse(response *ResponseAction) {
	rm.logger.Debug("Processing response: %s for threat: %s",
		response.ActionType, response.ThreatInfo.ThreatName)

	// Log response action
	rm.logger.Info("Response completed: %s (Severity: %d, Suppressed: %v)",
		response.ActionType, response.Severity, response.Suppressed)
}

func (rm *ResponseManager) sendToServerSafe(threat *models.ThreatInfo, response *ResponseAction) {
	defer func() {
		if r := recover(); r != nil {
			rm.logger.Error("Panic in server communication: %v", r)
		}
	}()

	rm.sendToServer(threat, response)
}

func (rm *ResponseManager) sendToServer(threat *models.ThreatInfo, response *ResponseAction) {
	if rm.serverClient == nil {
		return
	}

	// Create alert data
	alertData := map[string]interface{}{
		"rule_name":          threat.ThreatName,
		"title":              fmt.Sprintf("EDR Security Alert - %s", threat.ThreatName),
		"description":        threat.Description,
		"file_path":          threat.FilePath,
		"file_name":          filepath.Base(threat.FilePath),
		"severity":           threat.Severity,
		"action_type":        response.ActionType,
		"auto_executed":      response.AutoExecuted,
		"user_notified":      response.UserNotified,
		"suppressed":         response.Suppressed,
		"suppression_reason": response.SuppressionReason,
		"detection_time":     response.Timestamp.Format(time.RFC3339),
		"status":             "new",
		"event_type":         "threat_detection",
		"timestamp":          response.Timestamp,
		"evidence":           response.Evidence,
		"threat_type":        threat.ThreatType,
		"confidence":         threat.Confidence,
		"mitre_technique":    threat.MITRETechnique,
		"yara_rules":         threat.YaraRules,
	}

	// Send to server
	if sendAlert, ok := rm.serverClient.(interface {
		SendAlert(data map[string]interface{}) error
	}); ok {
		if err := sendAlert.SendAlert(alertData); err != nil {
			rm.logger.Debug("Failed to send alert to server: %v", err)
		} else {
			rm.logger.Debug("Alert sent to server successfully")
		}
	}
}

func (rm *ResponseManager) cleanupWorker() {
	ticker := time.NewTicker(15 * time.Minute) // More frequent cleanup
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

func (rm *ResponseManager) cleanup() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	cutoff := time.Now().Add(-6 * time.Hour) // Reduced retention time

	// Clean up old threats
	for filePath, threat := range rm.activeThreats {
		if threat.Timestamp.Before(cutoff) {
			delete(rm.activeThreats, filePath)
		}
	}

	// Clean up processed threats tracking
	for key, timestamp := range rm.processedThreats {
		if timestamp.Before(cutoff) {
			delete(rm.processedThreats, key)
		}
	}

	// Reset suppression counts periodically (clear all to prevent growth)
	if len(rm.suppressedThreats) > 0 {
		rm.suppressedThreats = make(map[string]int)
	}

	rm.logger.Debug("Cleanup completed - Active threats: %d, Processed tracking: %d",
		len(rm.activeThreats), len(rm.processedThreats))
}

func (rm *ResponseManager) isWhitelisted(filePath string) bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.whitelist[filePath]
}

func (rm *ResponseManager) AddToWhitelist(filePath string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.whitelist[filePath] = true
	rm.logger.Info("Added to whitelist: %s", filePath)
}

func (rm *ResponseManager) RemoveFromWhitelist(filePath string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	delete(rm.whitelist, filePath)
	rm.logger.Info("Removed from whitelist: %s", filePath)
}

func (rm *ResponseManager) GetActiveThreats() []*models.ThreatInfo {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	threats := make([]*models.ThreatInfo, 0, len(rm.activeThreats))
	for _, threat := range rm.activeThreats {
		threats = append(threats, threat)
	}
	return threats
}

func (rm *ResponseManager) GetQuarantineList() map[string]bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	result := make(map[string]bool)
	for k, v := range rm.quarantineList {
		result[k] = v
	}
	return result
}

// GetStats returns performance statistics
func (rm *ResponseManager) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	return map[string]interface{}{
		"total_threats":       rm.totalThreats,
		"processed_count":     rm.processedCount,
		"suppressed_count":    rm.suppressedCount,
		"quarantine_count":    rm.quarantineCount,
		"notification_count":  rm.notificationCount,
		"active_threats":      len(rm.activeThreats),
		"whitelisted_files":   len(rm.whitelist),
		"threat_queue_size":   len(rm.threatChan),
		"response_queue_size": len(rm.responseChan),
	}
}
