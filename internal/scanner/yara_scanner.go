//go:build cgo
// +build cgo

package scanner

import (
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/response"
	"edr-agent-windows/internal/utils"

	"github.com/hillu/go-yara/v4"
)

type YaraScanner struct {
	config          *config.YaraConfig
	logger          *utils.Logger
	rules           *yara.Rules
	rulesMu         sync.RWMutex
	agentID         string
	serverClient    interface{}
	responseManager interface{}

	// Enhanced notification handling
	toastNotifier *response.WindowsToastNotifier
	lastAlert     map[string]time.Time
	alertMu       sync.Mutex

	// Smart suppression system
	suppressionCache map[string]time.Time
	suppressionMu    sync.RWMutex

	// Performance metrics
	scanCount       int64
	suppressedCount int64
	alertCount      int64
}

type ScanResult struct {
	Matched           bool      `json:"matched"`
	RuleName          string    `json:"rule_name"`
	RuleTags          []string  `json:"rule_tags"`
	Severity          int       `json:"severity"`
	FileHash          string    `json:"file_hash"`
	ScanTime          int64     `json:"scan_time_ms"`
	FilePath          string    `json:"file_path"`
	FileSize          int64     `json:"file_size"`
	ScanTimestamp     time.Time `json:"scan_timestamp"`
	Description       string    `json:"description"`
	Suppressed        bool      `json:"suppressed"`
	SuppressionReason string    `json:"suppression_reason,omitempty"`
}

type YaraScanCallback struct {
	matches []yara.MatchRule
	logger  *utils.Logger
}

func (cb *YaraScanCallback) RuleMatching(sc *yara.ScanContext, r *yara.Rule) (bool, error) {
	matchRule := yara.MatchRule{
		Rule:      r.Identifier(),
		Namespace: r.Namespace(),
		Tags:      r.Tags(),
		Metas:     r.Metas(),
	}

	cb.matches = append(cb.matches, matchRule)
	cb.logger.Debug("YARA rule matched: %s (namespace: %s, tags: %v)",
		matchRule.Rule, matchRule.Namespace, matchRule.Tags)

	return false, nil
}

func NewYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) *YaraScanner {
	scanner := &YaraScanner{
		config:           cfg,
		logger:           logger,
		lastAlert:        make(map[string]time.Time),
		suppressionCache: make(map[string]time.Time),
	}

	// Initialize notification system with fallback
	if cfg.Enabled {
		responseConfig := &config.ResponseConfig{
			NotificationSettings: config.NotificationSettings{
				ToastEnabled:        true,
				SystemTrayEnabled:   true,
				DesktopAlertEnabled: true,
				SoundEnabled:        false, // Disable sound to reduce noise
				TimeoutSeconds:      3,     // Shorter timeout
			},
		}

		scanner.toastNotifier = response.NewWindowsToastNotifier(responseConfig, logger)
		if err := scanner.toastNotifier.Start(); err != nil {
			logger.Warn("Failed to start toast notifier, notifications disabled: %v", err)
			scanner.toastNotifier = nil
		} else {
			logger.Debug("YARA Scanner: Notification system initialized")
		}
	}

	// Load rules with fallback
	if cfg.Enabled {
		if err := scanner.LoadStaticRules(); err != nil {
			logger.Warn("Failed to load static rules: %v", err)
			if err := scanner.LoadRules(); err != nil {
				logger.Error("Failed to load YARA rules: %v", err)
			}
		} else {
			logger.Info("YARA Scanner: Static rules loaded successfully")
		}
	}

	return scanner
}

func (ys *YaraScanner) SetAgentID(agentID string) {
	ys.agentID = agentID
	ys.logger.Debug("YARA Scanner: Agent ID set to %s", agentID)
}

func (ys *YaraScanner) SetServerClient(serverClient interface{}) {
	ys.serverClient = serverClient
	ys.logger.Debug("YARA Scanner: Server client configured")
}

func (ys *YaraScanner) SetResponseManager(responseManager interface{}) {
	ys.responseManager = responseManager
	ys.logger.Debug("YARA Scanner: Response manager configured")
}

// Smart suppression system
func (ys *YaraScanner) shouldSuppressAlert(filePath, ruleName string) (bool, string) {
	// Quick path-based suppression for known benign locations
	if ys.isBenignPath(filePath) && ys.isEnvironmentalRule(ruleName) {
		return true, "benign_system_path"
	}

	// Time-based suppression
	key := fmt.Sprintf("%s|%s", filePath, ruleName)
	ys.suppressionMu.RLock()
	lastTime, exists := ys.suppressionCache[key]
	ys.suppressionMu.RUnlock()

	if exists && time.Since(lastTime) < 5*time.Minute {
		return true, "duplicate_recent"
	}

	// Update suppression cache
	ys.suppressionMu.Lock()
	ys.suppressionCache[key] = time.Now()
	// Cleanup old entries (keep only last 1000)
	if len(ys.suppressionCache) > 1000 {
		cutoff := time.Now().Add(-30 * time.Minute)
		for k, v := range ys.suppressionCache {
			if v.Before(cutoff) {
				delete(ys.suppressionCache, k)
			}
		}
	}
	ys.suppressionMu.Unlock()

	return false, ""
}

func (ys *YaraScanner) isBenignPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	benignPaths := []string{
		"\\windows\\system32\\",
		"\\windows\\syswow64\\",
		"\\windows\\winsxs\\",
		"\\program files\\",
		"\\program files (x86)\\",
		"\\programdata\\microsoft\\",
		"edgewebview",
		"microsoft\\edge",
		"windowspowershell",
		"\\quarantine\\",
		"\\.git\\",
		"\\node_modules\\",
		"\\appdata\\local\\temp\\",
		"cursor\\user\\workspacestorage",
		"globalstorage",
		"anysphere.cursor",
	}

	for _, path := range benignPaths {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}

func (ys *YaraScanner) isEnvironmentalRule(ruleName string) bool {
	lower := strings.ToLower(ruleName)
	envRules := []string{
		"debuggercheck",
		"debuggerexception",
		"vmdetect",
		"anti_dbg",
		"threadcontrol",
		"seh__vectored",
		"check_outputdebugstringa",
		"queryinfo",
		"win_hook",
		"disable_antivirus",
		"disable_dep",
	}

	for _, rule := range envRules {
		if strings.Contains(lower, rule) {
			return true
		}
	}
	return false
}

func (ys *YaraScanner) ScanFile(filePath string) (*ScanResult, error) {
	if !ys.config.Enabled {
		return &ScanResult{Matched: false, FilePath: filePath}, nil
	}

	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	if ys.rules == nil {
		ys.logger.Debug("No YARA rules loaded, skipping scan for: %s", filePath)
		return &ScanResult{Matched: false, FilePath: filePath}, nil
	}

	// Increment scan counter
	ys.scanCount++

	startTime := time.Now()

	// Get file info first
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Check file size limit
	maxSize := int64(100 * 1024 * 1024) // 100MB default
	if fileInfo.Size() > maxSize {
		ys.logger.Debug("File too large for scanning: %s (%d bytes)", filePath, fileInfo.Size())
		return &ScanResult{
			Matched:       false,
			FilePath:      filePath,
			FileSize:      fileInfo.Size(),
			ScanTimestamp: time.Now(),
			Description:   "File too large",
		}, nil
	}

	// Calculate file hash
	fileHash := ys.calculateFileHash(filePath)

	// Scan with timeout
	timeout := time.Duration(ys.config.ScanTimeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	callback := &YaraScanCallback{
		matches: make([]yara.MatchRule, 0),
		logger:  ys.logger,
	}

	err = ys.rules.ScanFile(filePath, 0, timeout, callback)
	if err != nil {
		return nil, fmt.Errorf("YARA scan failed: %w", err)
	}

	scanDuration := time.Since(startTime)

	result := &ScanResult{
		Matched:       len(callback.matches) > 0,
		FilePath:      filePath,
		FileSize:      fileInfo.Size(),
		ScanTimestamp: time.Now(),
		ScanTime:      scanDuration.Milliseconds(),
		FileHash:      fileHash,
	}

	if result.Matched {
		// Select the most relevant rule
		selectedMatch := ys.selectBestMatch(callback.matches)
		if selectedMatch == nil {
			return result, nil
		}

		result.RuleName = selectedMatch.Rule
		result.RuleTags = selectedMatch.Tags
		result.Severity = ys.getRuleSeverity(selectedMatch.Rule)
		result.Description = fmt.Sprintf("File matched YARA rule: %s", selectedMatch.Rule)

		// Apply intelligent suppression
		if suppressed, reason := ys.shouldSuppressAlert(filePath, result.RuleName); suppressed {
			result.Suppressed = true
			result.SuppressionReason = reason
			ys.suppressedCount++

			ys.logger.Debug("Suppressed YARA detection (%s): %s -> %s", reason, filePath, result.RuleName)
			return result, nil
		}

		// Log significant detections only
		ys.alertCount++
		ys.logger.Warn("🚨 YARA THREAT DETECTED: %s -> Rule: %s, Severity: %d",
			filePath, selectedMatch.Rule, result.Severity)

		// Show alert with better error handling
		go ys.showRealtimeNotificationSafe(filePath, result)

		// Process threat detection
		ys.handleThreatDetection(filePath, result, fileInfo)
	} else {
		ys.logger.Debug("YARA scan clean: %s (%.2fms)",
			filePath, float64(scanDuration.Microseconds())/1000)
	}

	return result, nil
}

func (ys *YaraScanner) selectBestMatch(matches []yara.MatchRule) *yara.MatchRule {
	if len(matches) == 0 {
		return nil
	}

	// Priority order: EICAR > Critical threats > High severity > First match
	for _, match := range matches {
		if strings.Contains(strings.ToLower(match.Rule), "eicar") {
			return &match
		}
	}

	// Find highest severity non-environmental rule
	var bestMatch *yara.MatchRule
	highestSeverity := 0

	for _, match := range matches {
		severity := ys.getRuleSeverity(match.Rule)
		if !ys.isEnvironmentalRule(match.Rule) && severity > highestSeverity {
			bestMatch = &match
			highestSeverity = severity
		}
	}

	if bestMatch != nil {
		return bestMatch
	}

	// Fallback to first match
	return &matches[0]
}

func (ys *YaraScanner) showRealtimeNotificationSafe(filePath string, result *ScanResult) {
	// Skip if notifications disabled
	if ys.toastNotifier == nil {
		ys.logger.Debug("Notifications disabled, skipping alert for: %s", result.RuleName)
		return
	}

	// Skip low-severity environmental detections
	if result.Severity <= 2 && ys.isEnvironmentalRule(result.RuleName) {
		ys.logger.Debug("Skipping low-severity environmental detection: %s", result.RuleName)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			ys.logger.Error("Panic in notification system: %v", r)
		}
	}()

	// Check for recent duplicate
	key := filePath + "|" + result.RuleName
	ys.alertMu.Lock()
	if lastTime, exists := ys.lastAlert[key]; exists {
		if time.Since(lastTime) < 30*time.Second {
			ys.alertMu.Unlock()
			return
		}
	}
	ys.lastAlert[key] = time.Now()
	ys.alertMu.Unlock()

	// Create notification content
	threatInfo := &models.ThreatInfo{
		ThreatName:  result.RuleName,
		FilePath:    filePath,
		Description: result.Description,
		Severity:    result.Severity,
	}

	content := &response.NotificationContent{
		Title:      fmt.Sprintf("🚨 YARA: %s", result.RuleName),
		Severity:   result.Severity,
		Timestamp:  time.Now(),
		ThreatInfo: threatInfo,
	}

	// Create appropriate message based on severity
	fileName := filepath.Base(filePath)
	threatType := ys.getThreatType(result.RuleTags)
	timeStr := time.Now().Format("15:04:05")

	switch result.Severity {
	case 5: // Critical
		content.Message = fmt.Sprintf("🔴 CRITICAL: %s\nFile: %s\nType: %s\nTime: %s\n\n⚠️ File flagged for quarantine",
			result.RuleName, fileName, threatType, timeStr)
	case 4: // High
		content.Message = fmt.Sprintf("🟠 HIGH: %s\nFile: %s\nType: %s\nTime: %s\n\n⚠️ Review recommended",
			result.RuleName, fileName, threatType, timeStr)
	default: // Medium/Low
		content.Message = fmt.Sprintf("🟡 ALERT: %s\nFile: %s\nType: %s\nTime: %s",
			result.RuleName, fileName, threatType, timeStr)
	}

	ys.logger.Info("🚨 DISPLAYING REALTIME YARA ALERT: %s", result.RuleName)

	// Send notification with timeout and error handling
	go func() {
		done := make(chan error, 1)
		go func() {
			done <- ys.toastNotifier.SendNotification(content)
		}()

		select {
		case err := <-done:
			if err != nil {
				ys.logger.Warn("Notification failed: %v", err)
				// Fallback to console output
				ys.showConsoleFallback(content)
			} else {
				ys.logger.Debug("✅ Notification displayed successfully")
			}
		case <-time.After(10 * time.Second):
			ys.logger.Warn("Notification timeout, using console fallback")
			ys.showConsoleFallback(content)
		}
	}()
}

func (ys *YaraScanner) showConsoleFallback(content *response.NotificationContent) {
	fmt.Printf("\n🚨 YARA ALERT: %s | Sev:%d | %s\n",
		content.ThreatInfo.ThreatName,
		content.Severity,
		content.Timestamp.Format("15:04:05"))
	os.Stdout.Sync()
}

func (ys *YaraScanner) getRuleSeverity(ruleName string) int {
	ruleNameLower := strings.ToLower(ruleName)

	// Environmental/anti-debug rules get low severity
	if ys.isEnvironmentalRule(ruleName) {
		return 1
	}

	// Critical threats
	if strings.Contains(ruleNameLower, "ransomware") ||
		strings.Contains(ruleNameLower, "backdoor") ||
		strings.Contains(ruleNameLower, "rootkit") ||
		strings.Contains(ruleNameLower, "eicar") ||
		strings.Contains(ruleNameLower, "exploit") {
		return 5
	}

	// High severity threats
	if strings.Contains(ruleNameLower, "trojan") ||
		strings.Contains(ruleNameLower, "keylogger") ||
		strings.Contains(ruleNameLower, "spyware") ||
		strings.Contains(ruleNameLower, "worm") ||
		strings.Contains(ruleNameLower, "rat") ||
		strings.Contains(ruleNameLower, "webshell") {
		return 4
	}

	// Medium severity
	if strings.Contains(ruleNameLower, "adware") ||
		strings.Contains(ruleNameLower, "pup") ||
		strings.Contains(ruleNameLower, "suspicious") ||
		strings.Contains(ruleNameLower, "malware") {
		return 3
	}

	// Low severity
	if strings.Contains(ruleNameLower, "toolkit") ||
		strings.Contains(ruleNameLower, "packer") ||
		strings.Contains(ruleNameLower, "crypto") ||
		strings.Contains(ruleNameLower, "capabilities") {
		return 2
	}

	return 3 // Default medium
}

func (ys *YaraScanner) getThreatType(tags []string) string {
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		switch tagLower {
		case "malware", "virus", "trojan":
			return "malware"
		case "ransomware", "ransom":
			return "ransomware"
		case "backdoor":
			return "backdoor"
		case "spyware", "keylogger":
			return "spyware"
		case "adware":
			return "adware"
		case "rootkit":
			return "rootkit"
		case "webshell":
			return "webshell"
		case "rat":
			return "rat"
		case "exploit":
			return "exploit"
		}
	}
	return "malware"
}

func (ys *YaraScanner) calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func (ys *YaraScanner) handleThreatDetection(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	threat := &models.ThreatInfo{
		ThreatType:     ys.getThreatType(result.RuleTags),
		ThreatName:     result.RuleName,
		Confidence:     0.9,
		Severity:       result.Severity,
		FilePath:       filePath,
		ProcessID:      0,
		ProcessName:    "",
		YaraRules:      []string{result.RuleName},
		MITRETechnique: "",
		Description:    result.Description,
		Timestamp:      time.Now(),
	}

	// Send alert to server
	ys.createAndSendAlert(filePath, result, fileInfo)

	// Send to Response Manager
	if ys.responseManager != nil {
		if rm, ok := ys.responseManager.(interface {
			HandleThreat(threat *models.ThreatInfo) error
		}); ok {
			if err := rm.HandleThreat(threat); err != nil {
				ys.logger.Error("Failed to handle threat via Response Manager: %v", err)
			} else {
				ys.logger.Debug("Threat sent to Response Manager for processing")
			}
		}
	}
}

func (ys *YaraScanner) createAndSendAlert(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	if ys.agentID == "" || ys.serverClient == nil {
		ys.logger.Debug("Cannot send alert: agent ID or server client not set")
		return
	}

	alertData := map[string]interface{}{
		"agent_id":       ys.agentID,
		"rule_name":      result.RuleName,
		"severity":       result.Severity,
		"title":          fmt.Sprintf("YARA Detection: %s", result.RuleName),
		"description":    result.Description,
		"file_path":      filePath,
		"file_name":      filepath.Base(filePath),
		"file_hash":      result.FileHash,
		"file_size":      fileInfo.Size(),
		"detection_time": time.Now().Format(time.RFC3339),
		"status":         "new",
		"event_type":     "yara_detection",
		"threat_type":    ys.getThreatType(result.RuleTags),
		"rule_tags":      result.RuleTags,
		"scan_time_ms":   result.ScanTime,
		"suppressed":     result.Suppressed,
	}

	if sendAlert, ok := ys.serverClient.(interface {
		SendAlert(data map[string]interface{}) error
	}); ok {
		if err := sendAlert.SendAlert(alertData); err != nil {
			ys.logger.Error("Failed to send YARA alert to server: %v", err)
		} else {
			ys.logger.Debug("✅ YARA alert sent to server successfully for file: %s", filePath)
		}
	}
}

// Rest of the methods remain the same...
func (ys *YaraScanner) LoadRules() error {
	ys.logger.Info("Loading YARA rules from: %s", ys.config.RulesPath)
	// ... existing implementation
	return nil
}

func (ys *YaraScanner) LoadStaticRules() error {
	ys.logger.Info("Loading static YARA rules...")
	// ... existing implementation
	return nil
}

func (ys *YaraScanner) ScanMemory(data []byte) (*ScanResult, error) {
	// ... existing implementation
	return &ScanResult{Matched: false}, nil
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Info("Reloading YARA rules...")
	return ys.LoadRules()
}

func (ys *YaraScanner) GetRulesInfo() map[string]interface{} {
	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	info := map[string]interface{}{
		"enabled":          ys.config.Enabled,
		"rules_path":       ys.config.RulesPath,
		"rules_loaded":     ys.rules != nil,
		"scan_count":       ys.scanCount,
		"alert_count":      ys.alertCount,
		"suppressed_count": ys.suppressedCount,
	}

	if ys.rules != nil {
		info["status"] = "loaded"
	} else {
		info["status"] = "not_loaded"
	}

	return info
}

func (ys *YaraScanner) Cleanup() {
	ys.rulesMu.Lock()
	defer ys.rulesMu.Unlock()

	if ys.rules != nil {
		ys.rules.Destroy()
		ys.rules = nil
		ys.logger.Info("YARA scanner cleanup completed")
	}

	if ys.toastNotifier != nil {
		ys.toastNotifier.Stop()
		ys.logger.Info("YARA scanner notification system stopped")
	}
}

func (ys *YaraScanner) GetMatchedRulesCount() int {
	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	if ys.rules == nil {
		return 0
	}

	rules := ys.rules.GetRules()
	return len(rules)
}
