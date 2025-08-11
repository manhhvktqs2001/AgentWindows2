package scanner

import (
<<<<<<< HEAD
	"bytes"
=======
	"bufio"
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
<<<<<<< HEAD
=======
	"sync"
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	"time"

	"edr-agent-windows/internal/communication"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/response"
	"edr-agent-windows/internal/utils"
)

// YaraScanner implements YARA-based file scanning using external yara64.exe
type YaraScanner struct {
	config          *config.YaraConfig
	logger          *utils.Logger
	serverClient    *communication.ServerClient
	responseManager *response.ResponseManager
    yaraExePath     string
	rulesPath       string
	agentID         string
<<<<<<< HEAD
}

func NewYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) *YaraScanner {
    exe := strings.TrimSpace(cfg.Executable)
    if exe == "" {
        exe = "yara64.exe"
    }
    return &YaraScanner{
        config:      cfg,
        logger:      logger,
        yaraExePath: exe,
        rulesPath:   cfg.RulesPath,
    }
}

func (ys *YaraScanner) SetServerClient(client *communication.ServerClient) { ys.serverClient = client }
func (ys *YaraScanner) SetResponseManager(rm *response.ResponseManager)    { ys.responseManager = rm }
func (ys *YaraScanner) SetAgentID(agentID string)                          { ys.agentID = agentID }

func (ys *YaraScanner) LoadRules() error {
	if !ys.config.Enabled {
		return nil
=======
	serverClient    interface{}
	responseManager interface{}

	// Enhanced suppression system
	recentAlerts     map[string]time.Time
	suppressionCache map[string]int // Track suppression counts
	recentMu         sync.Mutex

	// Direct notification components
	toastNotifier *response.WindowsToastNotifier
	lastAlert     map[string]time.Time
	alertMu       sync.Mutex

	// Performance tracking
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

func NewYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) *YaraScanner {
	logger.Warn("YARA Scanner: Running in stub mode (CGO disabled)")
	scanner := &YaraScanner{
		config:           cfg,
		logger:           logger,
		recentAlerts:     make(map[string]time.Time),
		suppressionCache: make(map[string]int),
		lastAlert:        make(map[string]time.Time),
	}

	// Initialize notification system
	if cfg.Enabled {
		responseConfig := &config.ResponseConfig{
			NotificationSettings: config.NotificationSettings{
				ToastEnabled:        true,
				SystemTrayEnabled:   true,
				DesktopAlertEnabled: true,
				SoundEnabled:        false, // Reduce noise
				TimeoutSeconds:      5,     // Shorter timeout
			},
		}

		scanner.toastNotifier = response.NewWindowsToastNotifier(responseConfig, logger)
		if err := scanner.toastNotifier.Start(); err != nil {
			logger.Warn("Failed to start toast notifier in YARA scanner (stub): %v", err)
			scanner.toastNotifier = nil
		} else {
			logger.Info("✅ YARA Scanner (Stub): Notification system ready")
		}
	}

	return scanner
}

func (ys *YaraScanner) SetAgentID(agentID string) {
	ys.agentID = agentID
	ys.logger.Debug("YARA Scanner Stub: Agent ID set to %s", agentID)
}

func (ys *YaraScanner) SetServerClient(serverClient interface{}) {
	ys.serverClient = serverClient
	ys.logger.Debug("YARA Scanner Stub: Server client configured")
}

func (ys *YaraScanner) SetResponseManager(responseManager interface{}) {
	ys.responseManager = responseManager
	ys.logger.Debug("YARA Scanner Stub: Response manager configured")
}

func (ys *YaraScanner) LoadRules() error {
	ys.logger.Info("YARA Scanner Stub: LoadRules called (no-op)")
	return nil
}

func (ys *YaraScanner) ScanFile(filePath string) (*ScanResult, error) {
	ys.scanCount++
	ys.logger.Debug("YARA Scanner Stub: Scan requested for: %s", filePath)

	// Enhanced suppression logic BEFORE scanning
	if ys.shouldSuppressBeforeScan(filePath) {
		ys.suppressedCount++
		return &ScanResult{
			Matched:           false,
			FilePath:          filePath,
			ScanTime:          time.Now().UnixMilli(),
			ScanTimestamp:     time.Now(),
			Description:       "suppressed before scan",
			Suppressed:        true,
			SuppressionReason: "development_path",
		}, nil
	}

	// Try external yara64.exe if available
	if ys.config != nil && ys.config.Enabled && ys.config.RulesPath != "" {
		if result, used, err := ys.scanWithExternalYara(filePath); used {
			if err != nil {
				return &ScanResult{
					Matched:       false,
					FilePath:      filePath,
					ScanTime:      time.Now().UnixMilli(),
					ScanTimestamp: time.Now(),
					Description:   fmt.Sprintf("External YARA scan error: %v", err),
				}, nil
			}

			if result != nil && result.Matched {
				// Enhanced suppression logic
				if suppressed, reason := ys.shouldSuppressDetection(filePath, result.RuleName); suppressed {
					ys.suppressedCount++
					result.Suppressed = true
					result.SuppressionReason = reason
					ys.logger.Debug("Suppressed YARA detection (%s): %s -> %s", reason, filePath, result.RuleName)
					return result, nil
				}

				// Advanced deduplication
				if ys.shouldSuppressDuplicate(filePath, result.RuleName, 2*time.Minute) {
					ys.suppressedCount++
					result.Suppressed = true
					result.SuppressionReason = "duplicate_recent"
					ys.logger.Debug("Suppressed duplicate YARA alert: %s | %s", filePath, result.RuleName)
					return result, nil
				}

				// Alert processing
				ys.alertCount++
				ys.announceDetection(filePath, result)
				ys.showRealtimeNotification(filePath, result)

				if fi, statErr := os.Stat(filePath); statErr == nil {
					ys.handleThreatDetection(filePath, result, fi)
				}

				return result, nil
			}
		}
	}

	// Fallback: EICAR pattern check
	content, err := os.ReadFile(filePath)
	if err != nil {
		return &ScanResult{
			Matched:       false,
			FilePath:      filePath,
			ScanTime:      time.Now().UnixMilli(),
			ScanTimestamp: time.Now(),
			Description:   "Failed to read file",
		}, nil
	}

	// Check for EICAR pattern
	if strings.Contains(string(content), "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") {
		result := &ScanResult{
			Matched:       true,
			FilePath:      filePath,
			RuleName:      "EICAR_Test_Stub",
			RuleTags:      []string{"test", "eicar", "stub"},
			Severity:      5,
			FileHash:      "stub_hash",
			ScanTime:      time.Now().UnixMilli(),
			ScanTimestamp: time.Now(),
			FileSize:      int64(len(content)),
			Description:   "EICAR test file detected by stub scanner",
		}

		if ys.shouldSuppressDuplicate(filePath, result.RuleName, 60*time.Second) {
			ys.suppressedCount++
			result.Suppressed = true
			result.SuppressionReason = "duplicate_recent"
			ys.logger.Debug("Suppressed duplicate EICAR alert: %s", filePath)
			return result, nil
		}

		ys.alertCount++
		ys.announceDetection(filePath, result)
		ys.showRealtimeNotification(filePath, result)

		if fi, statErr := os.Stat(filePath); statErr == nil {
			ys.handleThreatDetection(filePath, result, fi)
		}

		return result, nil
	}

	return &ScanResult{
		Matched:       false,
		FilePath:      filePath,
		ScanTime:      time.Now().UnixMilli(),
		ScanTimestamp: time.Now(),
		Description:   "YARA scanning disabled (CGO not available)",
	}, nil
}

// Enhanced suppression logic - check before scanning
func (ys *YaraScanner) shouldSuppressBeforeScan(filePath string) bool {
	if filePath == "" {
		return true
	}

	lowerPath := strings.ToLower(filePath)

	// Development/source code paths that should never be scanned
	developmentPaths := []string{
		"\\agentwindows\\",
		"\\internal\\",
		"\\pkg\\",
		"\\src\\",
		"\\vendor\\",
		"\\node_modules\\",
		"\\.git\\",
		"\\.vs\\",
		"\\.vscode\\",
		"\\go\\src\\",
		"\\go\\pkg\\",
		"\\temp\\go-build",
		"\\appdata\\local\\temp\\go-build",
		"\\users\\manh\\desktop\\agentwindows\\",
		"\\cursor\\user\\workspacestorage\\",
		"workspacestorage",
		"globalstorage",
		"anysphere.cursor",
	}

	for _, devPath := range developmentPaths {
		if strings.Contains(lowerPath, devPath) {
			return true
		}
	}

	return false
}

// Enhanced detection suppression logic
func (ys *YaraScanner) shouldSuppressDetection(filePath, ruleName string) (bool, string) {
	if filePath == "" || ruleName == "" {
		return false, ""
	}

	lowerPath := strings.ToLower(filePath)
	lowerRule := strings.ToLower(ruleName)

	// Environmental/anti-debug rules on system paths
	environmentalRules := []string{
		"debuggercheck", "debuggerexception", "vmdetect", "anti_dbg",
		"threadcontrol", "seh__vectored", "check_outputdebugstringa",
		"queryinfo", "win_hook", "disable_antivirus", "disable_dep",
		"setconsole", "setconsolectrl", "powershell", "capabilities",
		"antisandbox", "antivm", "antidebug", "antiemulatue", "antianalysis",
	}

	isEnvironmentalRule := false
	for _, envRule := range environmentalRules {
		if strings.Contains(lowerRule, envRule) {
			isEnvironmentalRule = true
			break
		}
	}

	// System and development paths
	systemPaths := []string{
		"\\windows\\system32\\", "\\windows\\syswow64\\", "\\program files\\",
		"\\program files (x86)\\", "edgewebview", "microsoft\\edge",
		"windowspowershell", "\\quarantine\\", "\\agentwindows\\",
		"\\internal\\", "\\users\\manh\\desktop\\agentwindows\\",
	}

	isSystemPath := false
	for _, sysPath := range systemPaths {
		if strings.Contains(lowerPath, sysPath) {
			isSystemPath = true
			break
		}
	}

	// Suppress environmental rules on system/dev paths
	if isEnvironmentalRule && isSystemPath {
		return true, "environmental_system_path"
	}

	// Suppress PowerShell rule on development paths specifically
	if strings.Contains(lowerRule, "powershell") &&
		(strings.Contains(lowerPath, "\\agentwindows\\") ||
			strings.Contains(lowerPath, "\\internal\\") ||
			strings.Contains(lowerPath, "\\users\\manh\\desktop\\agentwindows\\")) {
		return true, "powershell_development_path"
	}

	return false, ""
}

// Enhanced duplicate suppression with escalating timeouts
func (ys *YaraScanner) shouldSuppressDuplicate(filePath, rule string, window time.Duration) bool {
	key := filePath + "|" + rule

	ys.recentMu.Lock()
	defer ys.recentMu.Unlock()

	now := time.Now()

	// Check if we've seen this recently
	if lastTime, exists := ys.recentAlerts[key]; exists {
		timeSince := now.Sub(lastTime)

		// Escalating suppression window based on count
		count := ys.suppressionCache[key]
		escalatedWindow := window

		switch {
		case count >= 10:
			escalatedWindow = 30 * time.Minute // Heavy suppression
		case count >= 5:
			escalatedWindow = 10 * time.Minute // Medium suppression
		case count >= 2:
			escalatedWindow = 5 * time.Minute // Light suppression
		}

		if timeSince < escalatedWindow {
			ys.suppressionCache[key]++
			return true
		}
	}

	// Update tracking
	ys.recentAlerts[key] = now
	ys.suppressionCache[key]++

	// Cleanup old entries periodically
	if len(ys.recentAlerts) > 1000 {
		cutoff := now.Add(-1 * time.Hour)
		for k, v := range ys.recentAlerts {
			if v.Before(cutoff) {
				delete(ys.recentAlerts, k)
				delete(ys.suppressionCache, k)
			}
		}
	}

	return false
}

// Announce detection to console
func (ys *YaraScanner) announceDetection(filePath string, result *ScanResult) {
	fmt.Fprintf(os.Stdout, "\n🚨🚨🚨 YARA THREAT DETECTED! 🚨🚨🚨\n")
	fmt.Fprintf(os.Stdout, "File: %s\n", filePath)
	fmt.Fprintf(os.Stdout, "Rule: %s\n", result.RuleName)
	fmt.Fprintf(os.Stdout, "Severity: %d\n", result.Severity)
	fmt.Fprintf(os.Stdout, "Tags: %v\n", result.RuleTags)
	fmt.Fprintf(os.Stdout, "Description: %s\n", result.Description)
	fmt.Fprintf(os.Stdout, "🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")
	os.Stdout.Sync()
}

// Improved realtime notification with better error handling
func (ys *YaraScanner) showRealtimeNotification(filePath string, result *ScanResult) {
	if ys.toastNotifier == nil {
		ys.logger.Debug("Toast notifier not available, skipping notification")
		return
	}

	// Advanced deduplication for notifications
	key := filePath + "|" + result.RuleName
	ys.alertMu.Lock()
	if lastTime, exists := ys.lastAlert[key]; exists {
		if time.Since(lastTime) < 30*time.Second {
			ys.alertMu.Unlock()
			ys.logger.Debug("Suppressed duplicate notification: %s", key)
			return
		}
	}
	ys.lastAlert[key] = time.Now()
	ys.alertMu.Unlock()

	// Build notification content safely
	var threatInfo *models.ThreatInfo
	if result != nil {
		threatInfo = &models.ThreatInfo{
			ThreatName:  result.RuleName,
			FilePath:    filePath,
			Description: result.Description,
			Severity:    result.Severity,
		}
	}

	fileName := filepath.Base(filePath)
	if fileName == "" {
		fileName = "unknown file"
	}

	ruleName := "unknown rule"
	if result != nil && result.RuleName != "" {
		ruleName = result.RuleName
	}

	severity := 3
	if result != nil && result.Severity > 0 {
		severity = result.Severity
	}

	content := &response.NotificationContent{
		Title:      fmt.Sprintf("YARA: %s", ruleName),
		Severity:   severity,
		Timestamp:  time.Now(),
		ThreatInfo: threatInfo,
	}

	var threatType string
	if result != nil && len(result.RuleTags) > 0 {
		threatType = ys.getThreatType(result.RuleTags)
	} else {
		threatType = "unknown"
	}

	timeStr := time.Now().Format("15:04:05")

	switch severity {
	case 5: // Critical
		content.Message = fmt.Sprintf("🔴 CRITICAL: %s\nFile: %s\nType: %s\nTime: %s\n\n⚠️ Review required",
			ruleName, fileName, threatType, timeStr)
	case 4: // High
		content.Message = fmt.Sprintf("🟠 HIGH: %s\nFile: %s\nType: %s\nTime: %s\n\n⚠️ Review recommended",
			ruleName, fileName, threatType, timeStr)
	default: // Medium/Low
		content.Message = fmt.Sprintf("🟡 ALERT: %s\nFile: %s\nType: %s\nTime: %s",
			ruleName, fileName, threatType, timeStr)
	}

	ys.logger.Info("🚨 DISPLAYING REALTIME YARA ALERT (STUB): %s", ruleName)

	// Send notification with timeout protection
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ys.logger.Error("Panic in notification system: %v", r)
			}
		}()

		done := make(chan error, 1)
		go func() {
			done <- ys.toastNotifier.SendNotification(content)
		}()

		select {
		case err := <-done:
			if err != nil {
				ys.logger.Error("Notification failed: %v", err)
				ys.showFallbackAlert(filePath, result)
			} else {
				ys.logger.Info("✅ Realtime YARA notification displayed successfully")
			}
		case <-time.After(8 * time.Second):
			ys.logger.Error("Notification timeout, using fallback")
			ys.showFallbackAlert(filePath, result)
		}
	}()
}

// Fallback alert for notification failures
func (ys *YaraScanner) showFallbackAlert(filePath string, result *ScanResult) {
	var ruleName string
	var severity int

	if result != nil {
		ruleName = result.RuleName
		severity = result.Severity
	} else {
		ruleName = "unknown"
		severity = 3
	}

	fileName := filepath.Base(filePath)
	timeStr := time.Now().Format("15:04:05")

	// Console fallback
	fmt.Printf("\n🚨 YARA ALERT: %s | %s | sev=%d | %s\n", ruleName, fileName, severity, timeStr)
	os.Stdout.Sync()
}

// Enhanced external YARA scanning with better error handling
func (ys *YaraScanner) scanWithExternalYara(filePath string) (*ScanResult, bool, error) {
	yaraExe, err := exec.LookPath("yara64.exe")
	if err != nil {
		return nil, false, nil
	}

	rulesPath := ys.config.RulesPath
	if rulesPath == "" {
		return nil, true, fmt.Errorf("rules_path is empty")
	}

	// Build allowed categories
	allowed := make(map[string]struct{})
	for _, c := range ys.config.Categories {
		allowed[strings.ToLower(c)] = struct{}{}
	}
	if len(allowed) == 0 {
		for _, c := range []string{"malware", "maldocs", "webshells"} {
			allowed[c] = struct{}{}
		}
	}

	// Collect rule files
	ruleFiles := make([]string, 0, 64)
	_ = filepath.Walk(rulesPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" && ext != ".rule" && ext != ".rules" {
			return nil
		}
		rel, _ := filepath.Rel(rulesPath, path)
		segs := strings.Split(rel, string(os.PathSeparator))
		include := false
		for _, seg := range segs {
			if _, ok := allowed[strings.ToLower(seg)]; ok {
				include = true
				break
			}
		}
		if include {
			ruleFiles = append(ruleFiles, path)
			if len(ruleFiles) >= 100 {
				return fmt.Errorf("limit reached")
			}
		}
		return nil
	})

	if len(ruleFiles) == 0 {
		return nil, true, fmt.Errorf("no allowed rule files found")
	}

	// Scan with timeout
	timeoutSec := 30
	if ys.config.ScanTimeout > 0 {
		timeoutSec = ys.config.ScanTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	for _, ruleFile := range ruleFiles {
		cmd := exec.CommandContext(ctx, yaraExe, "-s", ruleFile, filePath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			continue
		}

		if err := cmd.Start(); err != nil {
			continue
		}

		scanner := bufio.NewScanner(stdout)
		var matchedRule string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) > 0 {
				matchedRule = parts[0]
				break
			}
		}
		_ = cmd.Wait()

		if matchedRule != "" {
			severity := ys.getRuleSeverityStub(matchedRule)
			result := &ScanResult{
				Matched:       true,
				FilePath:      filePath,
				RuleName:      matchedRule,
				RuleTags:      []string{"external"},
				Severity:      severity,
				FileHash:      "",
				ScanTime:      time.Now().UnixMilli(),
				ScanTimestamp: time.Now(),
				Description:   fmt.Sprintf("Matched by external YARA rule: %s", filepath.Base(ruleFile)),
			}
			return result, true, nil
		}
	}

	return &ScanResult{
		Matched:       false,
		FilePath:      filePath,
		ScanTime:      time.Now().UnixMilli(),
		ScanTimestamp: time.Now(),
		Description:   "No match by external YARA",
	}, true, nil
}

// Enhanced severity mapping
func (ys *YaraScanner) getRuleSeverityStub(ruleName string) int {
	rn := strings.ToLower(ruleName)

	// Environmental/anti-debug rules get very low severity
	if strings.Contains(rn, "debuggercheck") ||
		strings.Contains(rn, "debuggerexception") ||
		strings.Contains(rn, "queryinfo") ||
		strings.Contains(rn, "vmdetect") ||
		strings.Contains(rn, "anti_dbg") ||
		strings.Contains(rn, "threadcontrol") ||
		strings.Contains(rn, "seh__vectored") ||
		strings.Contains(rn, "check_outputdebugstringa") ||
		strings.Contains(rn, "powershell") ||
		strings.Contains(rn, "capabilities") ||
		strings.Contains(rn, "antisandbox") ||
		strings.Contains(rn, "antivm") ||
		strings.Contains(rn, "antidebug") {
		return 1
	}

	// Critical threats
	if strings.Contains(rn, "ransomware") ||
		strings.Contains(rn, "backdoor") ||
		strings.Contains(rn, "rootkit") ||
		strings.Contains(rn, "eicar") ||
		strings.Contains(rn, "exploit") {
		return 5
	}

	// High severity threats
	if strings.Contains(rn, "trojan") ||
		strings.Contains(rn, "keylogger") ||
		strings.Contains(rn, "spyware") ||
		strings.Contains(rn, "worm") ||
		strings.Contains(rn, "rat") ||
		strings.Contains(rn, "webshell") ||
		strings.Contains(rn, "wshell") {
		return 4
	}

	// Medium severity
	if strings.Contains(rn, "adware") ||
		strings.Contains(rn, "pup") ||
		strings.Contains(rn, "suspicious") ||
		strings.Contains(rn, "malware") ||
		strings.Contains(rn, "malw") {
		return 3
	}

	// Low severity
	if strings.Contains(rn, "toolkit") ||
		strings.Contains(rn, "packer") ||
		strings.Contains(rn, "crypto") {
		return 2
	}

	return 3 // Default medium
}

// Handle threat detection with enhanced error handling
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
				ys.logger.Info("Threat sent to Response Manager for processing")
			}
		}
	}
}

// Create and send alert with enhanced validation
func (ys *YaraScanner) createAndSendAlert(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	if ys.agentID == "" || ys.serverClient == nil {
		ys.logger.Debug("Cannot send alert: agent ID or server client not set")
		return
	}

	ruleName := result.RuleName
	if ruleName == "" {
		ruleName = "unknown_rule"
	}

	alertData := map[string]interface{}{
		"agent_id":       ys.agentID,
		"rule_name":      ruleName,
		"severity":       result.Severity,
		"title":          fmt.Sprintf("YARA Detection: %s", ruleName),
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
			ys.logger.Info("✅ YARA alert sent to server successfully for file: %s", filePath)
		}
	}
}

// Enhanced threat type detection
func (ys *YaraScanner) getThreatType(tags []string) string {
	if len(tags) == 0 {
		return "malware"
	}

	lowerTags := make([]string, 0, len(tags))
	for _, t := range tags {
		if t != "" {
			lowerTags = append(lowerTags, strings.ToLower(t))
		}
	}

	if len(lowerTags) == 0 {
		return "malware"
	}

	has := func(substr string) bool {
		for _, t := range lowerTags {
			if strings.Contains(t, substr) {
				return true
			}
		}
		return false
	}

	switch {
	case has("ransom"):
		return "ransomware"
	case has("bank") || has("credential") || has("steal"):
		return "credential_stealer"
	case has("spy") || has("keylog"):
		return "spyware"
	case has("worm"):
		return "worm"
	case has("trojan"):
		return "trojan"
	case has("rootkit"):
		return "rootkit"
	case has("backdoor"):
		return "backdoor"
	case has("webshell"):
		return "webshell"
	default:
		return "malware"
	}
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Info("YARA Scanner Stub: ReloadRules called (no-op)")
	return nil
}

func (ys *YaraScanner) GetRulesInfo() map[string]interface{} {
	return map[string]interface{}{
		"enabled":          ys.config.Enabled,
		"rules_path":       ys.config.RulesPath,
		"rules_loaded":     false,
		"status":           "stub_mode",
		"message":          "YARA scanning requires CGO",
		"scan_count":       ys.scanCount,
		"alert_count":      ys.alertCount,
		"suppressed_count": ys.suppressedCount,
>>>>>>> 00e9527bf4c697277e34f52d96c010daf1e280ef
	}
    // Try resolve via explicit path or PATH lookup
    resolvedExe := ys.resolveYaraExecutable()
    if resolvedExe == "" {
        ys.logger.Warn("yara executable not found; YARA scanning disabled")
        return fmt.Errorf("yara executable not found")
    }
    ys.yaraExePath = resolvedExe
	if _, err := os.Stat(ys.rulesPath); os.IsNotExist(err) {
		ys.logger.Warn("YARA rules directory not found: %s", ys.rulesPath)
		return fmt.Errorf("rules directory not found: %s", ys.rulesPath)
	}
	ys.logger.Info("YARA: external scanner ready (rules: %s)", ys.rulesPath)
	return nil
}

func (ys *YaraScanner) ScanFile(filePath string) (*models.ThreatInfo, error) {
	if !ys.config.Enabled {
		return nil, nil
	}
    if ys.resolveYaraExecutable() == "" {
        return nil, fmt.Errorf("yara executable not found")
    }
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file not found: %s", filePath)
	}

	args := []string{"-r", ys.rulesPath, filePath}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ys.config.ScanTimeout)*time.Second)
	defer cancel()
    cmd := exec.CommandContext(ctx, ys.yaraExePath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scan timeout")
	}
	out := strings.TrimSpace(stdout.String())
	if out == "" {
		return nil, nil
	}

	lines := strings.Split(out, "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, nil
	}
	ruleName := parts[0]
	matched := parts[1]

	threat := &models.ThreatInfo{
		ThreatType:  "malware",
		ThreatName:  ruleName,
		Confidence:  0.9,
		Severity:    ys.severityFromRule(ruleName),
		FilePath:    matched,
		ProcessID:   0,
		ProcessName: "",
		YaraRules:   []string{ruleName},
		Description: fmt.Sprintf("YARA matched rule %s on %s", ruleName, filepath.Base(matched)),
		Timestamp:   time.Now(),
	}

	// Hand off to ResponseManager for notifications and actions
	if ys.responseManager != nil {
		_ = ys.responseManager.HandleThreat(threat)
	}
	// Send alert to server
	ys.sendAlert(threat)
	return threat, nil
}

func (ys *YaraScanner) sendAlert(t *models.ThreatInfo) {
	if ys.serverClient == nil {
		return
	}
	payload := map[string]interface{}{
		"agent_id":    ys.serverClient.GetAgentID(),
		"event_type":  "alert",
		"timestamp":   time.Now().UTC(),
		"threat_info": t,
	}
	_ = ys.serverClient.SendAlert(payload)
}

// resolveYaraExecutable tries to find the configured executable. If the value is
// a relative name (e.g., "yara64.exe"), it searches in PATH.
func (ys *YaraScanner) resolveYaraExecutable() string {
    exe := strings.TrimSpace(ys.yaraExePath)
    if exe == "" {
        exe = "yara64.exe"
    }
    // If path exists as-is, use it
    if _, err := os.Stat(exe); err == nil {
        return exe
    }
    // Otherwise, look up in PATH
    found, err := exec.LookPath(exe)
    if err == nil && found != "" {
        return found
    }
    return ""
}

func (ys *YaraScanner) severityFromRule(name string) int {
	l := strings.ToLower(name)
	if strings.Contains(l, "ransom") || strings.Contains(l, "backdoor") || strings.Contains(l, "trojan") {
		return 5
	}
	if strings.Contains(l, "exploit") || strings.Contains(l, "maldoc") || strings.Contains(l, "webshell") {
		return 4
	}
	if strings.Contains(l, "antidebug") || strings.Contains(l, "antivm") {
		return 3
	}
	return 2
}

func (ys *YaraScanner) Cleanup() {
	ys.logger.Info("YARA scanner cleanup completed (stub)")
	if ys.toastNotifier != nil {
		ys.toastNotifier.Stop()
		ys.logger.Info("YARA scanner notification system stopped")
	}
}

func (ys *YaraScanner) GetMatchedRulesCount() int {
	return 0
}
