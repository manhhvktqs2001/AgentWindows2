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
	"edr-agent-windows/internal/utils"

	"github.com/hillu/go-yara/v4"
)

type YaraScanner struct {
	config          *config.YaraConfig
	logger          *utils.Logger
	rules           *yara.Rules
	rulesMu         sync.RWMutex
	agentID         string
	serverClient    interface{} // Server client để gửi alert
	responseManager interface{} // Response Manager để gửi cho Response System
}

type ScanResult struct {
	Matched       bool      `json:"matched"`
	RuleName      string    `json:"rule_name"`
	RuleTags      []string  `json:"rule_tags"`
	Severity      int       `json:"severity"`
	FileHash      string    `json:"file_hash"`
	ScanTime      int64     `json:"scan_time_ms"`
	FilePath      string    `json:"file_path"`
	FileSize      int64     `json:"file_size"`
	ScanTimestamp time.Time `json:"scan_timestamp"`
	Description   string    `json:"description"`
}

// YaraScanCallback implements the ScanCallback interface for go-yara v4
type YaraScanCallback struct {
	matches []yara.MatchRule
	logger  *utils.Logger
}

// RuleMatching implements the ScanCallbackMatch interface
// This is the correct signature for go-yara v4
func (cb *YaraScanCallback) RuleMatching(sc *yara.ScanContext, r *yara.Rule) (bool, error) {
	matchRule := yara.MatchRule{
		Rule:      r.Identifier(),
		Namespace: r.Namespace(),
		Tags:      r.Tags(),
		Metas:     r.Metas(),
		// Strings field intentionally left empty; retrieving match strings via ScanContext is not available here
	}

	cb.matches = append(cb.matches, matchRule)
	cb.logger.Debug("YARA rule matched: %s (namespace: %s, tags: %v)",
		matchRule.Rule, matchRule.Namespace, matchRule.Tags)

	return false, nil // Continue scanning (false = don't abort)
}

func NewYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) *YaraScanner {
	scanner := &YaraScanner{
		config: cfg,
		logger: logger,
	}

	// Load YARA rules nếu enabled
	if cfg.Enabled {
		// First try to load static rules
		err := scanner.LoadStaticRules()
		if err != nil {
			logger.Warn("Failed to load static rules: %v", err)
			// Fallback to file-based rules
			err = scanner.LoadRules()
			if err != nil {
				logger.Error("Failed to load YARA rules: %v", err)
			}
		} else {
			logger.Info("Static YARA rules loaded successfully")
		}
	}

	return scanner
}

// SetAgentID sets the agent ID for alert creation
func (ys *YaraScanner) SetAgentID(agentID string) {
	ys.agentID = agentID
	ys.logger.Debug("YARA Scanner: Agent ID set to %s", agentID)
}

// SetServerClient sets the server client for sending alerts
func (ys *YaraScanner) SetServerClient(serverClient interface{}) {
	ys.serverClient = serverClient
	ys.logger.Debug("YARA Scanner: Server client configured")
}

// SetResponseManager thiết lập Response Manager
func (ys *YaraScanner) SetResponseManager(responseManager interface{}) {
	ys.responseManager = responseManager
	ys.logger.Debug("YARA Scanner: Response manager configured")
}

func (ys *YaraScanner) LoadRules() error {
	ys.logger.Info("Loading YARA rules from: %s", ys.config.RulesPath)

	// Check if rules directory exists
	if _, err := os.Stat(ys.config.RulesPath); os.IsNotExist(err) {
		ys.logger.Warn("YARA rules directory does not exist: %s", ys.config.RulesPath)
		return ys.createDefaultRules()
	}

	// Compile rules from directory
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	rulesLoaded := 0
	errors := []string{}
	categories := make(map[string]int)

	// Walk through rules directory recursively
	err = filepath.Walk(ys.config.RulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			ys.logger.Warn("Error walking rules directory: %v", err)
			return nil // Continue processing other files
		}

		// Skip directories and non-YARA files
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		// Get category from path
		relPath, _ := filepath.Rel(ys.config.RulesPath, path)
		pathParts := strings.Split(relPath, string(os.PathSeparator))
		category := "unknown"
		if len(pathParts) > 0 {
			category = pathParts[0]
		}

		// Add rule file to compiler
		ruleFile, err := os.Open(path)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to open rule file %s: %v", path, err)
			ys.logger.Error(errorMsg)
			errors = append(errors, errorMsg)
			return nil // Continue with other files
		}
		defer ruleFile.Close()

		err = compiler.AddFile(ruleFile, filepath.Base(path))
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to compile rule file %s: %v", path, err)
			ys.logger.Error(errorMsg)
			errors = append(errors, errorMsg)
			return nil // Continue with other files
		}

		categories[category]++
		ys.logger.Debug("Added YARA rule file: %s (category: %s)", path, category)
		rulesLoaded++
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}

	// Log category statistics
	ys.logger.Info("YARA rules loaded by category:")
	for category, count := range categories {
		ys.logger.Info("  - %s: %d rules", category, count)
	}

	ys.logger.Info("Attempted to load %d YARA rule files", rulesLoaded)

	if rulesLoaded == 0 {
		ys.logger.Warn("No YARA rules loaded, creating default rules")
		return ys.createDefaultRules()
	}

	// Get compiled rules
	ys.rulesMu.Lock()
	defer ys.rulesMu.Unlock()

	ys.rules, err = compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to compile YARA rules: %w", err)
	}

	ys.logger.Info("YARA rules loaded successfully: %d rule files", rulesLoaded)

	// Log any compilation errors
	if len(errors) > 0 {
		ys.logger.Warn("Some YARA rules failed to compile:")
		for _, error := range errors {
			ys.logger.Warn("  - %s", error)
		}
	}

	return nil
}

// createDefaultRules tạo rules mặc định nếu không có rules
func (ys *YaraScanner) createDefaultRules() error {
	ys.logger.Info("Creating default YARA rules...")

	// Tạo thư mục rules nếu chưa có
	if err := os.MkdirAll(ys.config.RulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Tạo rule test cơ bản
	defaultRule := `rule EICAR_Test {
    meta:
        description = "EICAR Standard Anti-Virus Test File"
        author = "EDR System"
        severity = 4
        threat_type = "test"
        tags = "test eicar"
    
    strings:
        $eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar_string
}

rule TestMalware {
    meta:
        description = "Test rule to detect malware files"
        author = "EDR System"
        severity = 3
        threat_type = "malware"
        tags = "malware test"
    
    strings:
        $malware_string = "This is a test malware file for EDR testing"
    
    condition:
        $malware_string
}

rule TestRansomware {
    meta:
        description = "Test rule to detect ransomware patterns"
        author = "EDR System"
        severity = 5
        threat_type = "ransomware"
        tags = "ransomware test"
    
    strings:
        $encrypt_string = "encrypt"
        $ransom_string = "ransom"
        $bitcoin_string = "bitcoin"
        $payment_string = "payment"
    
    condition:
        2 of them
}`

	// Ghi default rule vào file
	ruleFile := filepath.Join(ys.config.RulesPath, "default_rules.yar")
	if err := os.WriteFile(ruleFile, []byte(defaultRule), 0644); err != nil {
		return fmt.Errorf("failed to create default rule file: %w", err)
	}

	ys.logger.Info("Default YARA rules created: %s", ruleFile)

	// Load lại rules
	return ys.LoadRules()
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

	startTime := time.Now()

	// Get file info first (không cần mở file để lấy info)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Check file size limit
	maxSize := int64(100 * 1024 * 1024) // 100MB default
	if ys.config.MaxFileSize != "" {
		// TODO: Parse max file size from config
	}

	if fileInfo.Size() > maxSize {
		ys.logger.Debug("File too large for scanning: %s (%d bytes)", filePath, fileInfo.Size())
		return &ScanResult{
			Matched:       false,
			FilePath:      filePath,
			FileSize:      fileInfo.Size(),
			ScanTimestamp: time.Now(),
		}, nil
	}

	// Calculate file hash
	fileHash := ys.calculateFileHash(filePath)

	// Scan file với timeout - CORRECT API USAGE cho go-yara v4
	timeout := time.Duration(ys.config.ScanTimeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second // Default 30 seconds
	}

	// Create callback để collect matches
	callback := &YaraScanCallback{
		matches: make([]yara.MatchRule, 0),
		logger:  ys.logger,
	}

	// Use CORRECT YARA v4 API: ScanFile với callback
	// Signature: ScanFile(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) error
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

	// Debug: Log scan results
	ys.logger.Debug("YARA scan completed for %s: %d matches found", filePath, len(callback.matches))
	if len(callback.matches) > 0 {
		for i, match := range callback.matches {
			ys.logger.Debug("Match %d: Rule=%s, Tags=%v", i+1, match.Rule, match.Tags)
		}
	}

	if result.Matched {
		// Print all matches - Force flush to ensure immediate display
		fmt.Fprintf(os.Stdout, "\n🚨🚨🚨 YARA THREAT DETECTED! 🚨🚨🚨\n")
		fmt.Fprintf(os.Stdout, "File: %s\n", filePath)
		fmt.Fprintf(os.Stdout, "Total Matches: %d\n", len(callback.matches))

		// Show all matching rules
		for i, match := range callback.matches {
			fmt.Fprintf(os.Stdout, "\nMatch %d:\n", i+1)
			fmt.Fprintf(os.Stdout, "  Rule: %s\n", match.Rule)
			fmt.Fprintf(os.Stdout, "  Tags: %v\n", match.Tags)
			fmt.Fprintf(os.Stdout, "  Namespace: %s\n", match.Namespace)
		}

		// Prioritize rules based on threat type and severity
		var selectedMatch *yara.MatchRule
		var highestSeverity int = 0

		// First, try to find EICAR rules (highest priority for testing)
		for _, match := range callback.matches {
			ruleNameLower := strings.ToLower(match.Rule)
			if strings.Contains(ruleNameLower, "eicar") {
				selectedMatch = &match
				break
			}
		}

		// If no EICAR rule found, prioritize by threat type
		if selectedMatch == nil {
			for _, match := range callback.matches {
				ruleNameLower := strings.ToLower(match.Rule)
				severity := ys.getRuleSeverity(match.Rule)

				// Prioritize ransomware, backdoor, rootkit (critical threats)
				if strings.Contains(ruleNameLower, "ransomware") ||
					strings.Contains(ruleNameLower, "backdoor") ||
					strings.Contains(ruleNameLower, "rootkit") {
					if severity > highestSeverity {
						selectedMatch = &match
						highestSeverity = severity
					}
				}
			}
		}

		// If still no specific rule found, prioritize by severity
		if selectedMatch == nil {
			for _, match := range callback.matches {
				severity := ys.getRuleSeverity(match.Rule)
				if severity > highestSeverity {
					selectedMatch = &match
					highestSeverity = severity
				}
			}
		}

		// If still no specific rule found, use first match
		if selectedMatch == nil && len(callback.matches) > 0 {
			selectedMatch = &callback.matches[0]
		}

		// If no matches found, this shouldn't happen but handle it
		if selectedMatch == nil {
			ys.logger.Error("No matching rule selected despite having matches")
			return result, nil
		}

		result.RuleName = selectedMatch.Rule
		result.RuleTags = selectedMatch.Tags
		result.Severity = ys.getRuleSeverity(selectedMatch.Rule)
		result.Description = fmt.Sprintf("File matched YARA rule: %s", selectedMatch.Rule)

		fmt.Fprintf(os.Stdout, "\nSelected Rule: %s\n", result.RuleName)
		fmt.Fprintf(os.Stdout, "Severity: %d\n", result.Severity)
		fmt.Fprintf(os.Stdout, "Tags: %v\n", result.RuleTags)
		fmt.Fprintf(os.Stdout, "Description: %s\n", result.Description)
		fmt.Fprintf(os.Stdout, "File Hash: %s\n", result.FileHash)
		fmt.Fprintf(os.Stdout, "File Size: %d bytes\n", result.FileSize)
		fmt.Fprintf(os.Stdout, "Scan Time: %dms\n", result.ScanTime)
		fmt.Fprintf(os.Stdout, "🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")

		// Force flush to ensure immediate display
		os.Stdout.Sync()

		ys.logger.Warn("🚨 YARA THREAT DETECTED: %s -> Rule: %s, Severity: %d",
			filePath, selectedMatch.Rule, result.Severity)

		// Xử lý threat detection
		ys.handleThreatDetection(filePath, result, fileInfo)
	} else {
		ys.logger.Debug("YARA scan clean: %s (%.2fms)", filePath, float64(scanDuration.Microseconds())/1000)
	}

	return result, nil
}

// ScanMemory scans in-memory data with YARA rules
func (ys *YaraScanner) ScanMemory(data []byte) (*ScanResult, error) {
	if !ys.config.Enabled {
		return &ScanResult{Matched: false}, nil
	}

	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	if ys.rules == nil {
		ys.logger.Debug("No YARA rules loaded, skipping memory scan")
		return &ScanResult{Matched: false}, nil
	}

	startTime := time.Now()

	// Scan timeout
	timeout := time.Duration(ys.config.ScanTimeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Create callback để collect matches
	callback := &YaraScanCallback{
		matches: make([]yara.MatchRule, 0),
		logger:  ys.logger,
	}

	// Use CORRECT YARA v4 API: ScanMem với callback
	err := ys.rules.ScanMem(data, 0, timeout, callback)
	if err != nil {
		return nil, fmt.Errorf("YARA memory scan failed: %w", err)
	}

	scanDuration := time.Since(startTime)

	result := &ScanResult{
		Matched:       len(callback.matches) > 0,
		FilePath:      "memory",
		FileSize:      int64(len(data)),
		ScanTimestamp: time.Now(),
		ScanTime:      scanDuration.Milliseconds(),
	}

	if result.Matched && len(callback.matches) > 0 {
		selectedMatch := &callback.matches[0] // Use first match for simplicity
		result.RuleName = selectedMatch.Rule
		result.RuleTags = selectedMatch.Tags
		result.Severity = ys.getRuleSeverity(selectedMatch.Rule)
		result.Description = fmt.Sprintf("Memory matched YARA rule: %s", selectedMatch.Rule)

		ys.logger.Warn("🚨 YARA MEMORY THREAT DETECTED: Rule: %s, Severity: %d",
			selectedMatch.Rule, result.Severity)
	}

	return result, nil
}

// handleThreatDetection xử lý khi phát hiện threat
func (ys *YaraScanner) handleThreatDetection(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	// Tạo ThreatInfo
	threat := &models.ThreatInfo{
		ThreatType:     ys.getThreatType(result.RuleTags),
		ThreatName:     result.RuleName,
		Confidence:     0.9, // High confidence cho YARA matches
		Severity:       result.Severity,
		FilePath:       filePath,
		ProcessID:      0,  // Will be set by process monitor if available
		ProcessName:    "", // Will be set by process monitor if available
		YaraRules:      []string{result.RuleName},
		MITRETechnique: "", // Could be extracted from rule metadata
		Description:    result.Description,
		Timestamp:      time.Now(),
	}

	// Gửi alert về server
	ys.createAndSendAlert(filePath, result, fileInfo)

	// Gửi cho Response Manager để xử lý (hiển thị notification, quarantine, etc.)
	if ys.responseManager != nil {
		if rm, ok := ys.responseManager.(interface {
			HandleThreat(threat *models.ThreatInfo) error
		}); ok {
			err := rm.HandleThreat(threat)
			if err != nil {
				ys.logger.Error("Failed to handle threat via Response Manager: %v", err)
			} else {
				ys.logger.Info("Threat sent to Response Manager for processing")
			}
		} else {
			ys.logger.Warn("Response Manager does not support HandleThreat method")
		}
	} else {
		ys.logger.Warn("Response Manager not configured - threat not processed")
	}
}

// createAndSendAlert tạo alert và gửi về server
func (ys *YaraScanner) createAndSendAlert(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	if ys.agentID == "" || ys.serverClient == nil {
		ys.logger.Warn("Cannot send alert: agent ID or server client not set")
		return
	}

	// Tạo alert data
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
	}

	// Gửi alert về server
	if sendAlert, ok := ys.serverClient.(interface {
		SendAlert(data map[string]interface{}) error
	}); ok {
		err := sendAlert.SendAlert(alertData)
		if err != nil {
			ys.logger.Error("Failed to send YARA alert to server: %v", err)
		} else {
			ys.logger.Info("✅ YARA alert sent to server successfully for file: %s", filePath)
		}
	} else {
		ys.logger.Warn("Server client does not support SendAlert method")
	}
}

// calculateFileHash tính MD5 hash của file
func (ys *YaraScanner) calculateFileHash(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		ys.logger.Debug("Failed to open file for hashing: %v", err)
		return ""
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		ys.logger.Debug("Failed to calculate file hash: %v", err)
		return ""
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// getRuleSeverity xác định severity từ rule name hoặc metadata
func (ys *YaraScanner) getRuleSeverity(ruleName string) int {
	ruleNameLower := strings.ToLower(ruleName)

	// De-emphasize environmental/anti-debug/vm rules commonly seen in benign system binaries
	if strings.Contains(ruleNameLower, "debuggercheck") ||
		strings.Contains(ruleNameLower, "vmdetect") ||
		strings.Contains(ruleNameLower, "anti_dbg") ||
		strings.Contains(ruleNameLower, "threadcontrol") ||
		strings.Contains(ruleNameLower, "seh__vectored") {
		return 1
	}

	// Critical severity (5) - Immediate action required
	if strings.Contains(ruleNameLower, "ransomware") ||
		strings.Contains(ruleNameLower, "backdoor") ||
		strings.Contains(ruleNameLower, "rootkit") ||
		strings.Contains(ruleNameLower, "eicar") ||
		strings.Contains(ruleNameLower, "exploit") {
		return 5
	}

	// High severity (4) - High priority threats
	if strings.Contains(ruleNameLower, "trojan") ||
		strings.Contains(ruleNameLower, "keylogger") ||
		strings.Contains(ruleNameLower, "spyware") ||
		strings.Contains(ruleNameLower, "worm") ||
		strings.Contains(ruleNameLower, "rat") ||
		strings.Contains(ruleNameLower, "webshell") ||
		strings.Contains(ruleNameLower, "wshell") {
		return 4
	}

	// Medium severity (3) - Moderate threats
	if strings.Contains(ruleNameLower, "adware") ||
		strings.Contains(ruleNameLower, "pup") ||
		strings.Contains(ruleNameLower, "suspicious") ||
		strings.Contains(ruleNameLower, "malware") ||
		strings.Contains(ruleNameLower, "malw") {
		return 3
	}

	// Low severity (2) - Minor threats
	if strings.Contains(ruleNameLower, "toolkit") ||
		strings.Contains(ruleNameLower, "packer") ||
		strings.Contains(ruleNameLower, "crypto") ||
		strings.Contains(ruleNameLower, "capabilities") {
		return 2
	}

	// Default medium severity
	return 3
}

// getThreatType xác định threat type từ rule tags
func (ys *YaraScanner) getThreatType(tags []string) string {
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		switch tagLower {
		case "malware", "virus", "trojan", "malw":
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
		case "webshell", "wshell":
			return "webshell"
		case "rat":
			return "rat"
		case "exploit":
			return "exploit"
		case "crypto":
			return "cryptominer"
		case "packer":
			return "packer"
		case "toolkit":
			return "toolkit"
		case "capabilities":
			return "capability"
		}
	}
	return "malware" // Default
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Info("Reloading YARA rules...")
	return ys.LoadRules()
}

// GetRulesInfo trả về thông tin về rules đã load
func (ys *YaraScanner) GetRulesInfo() map[string]interface{} {
	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	info := map[string]interface{}{
		"enabled":      ys.config.Enabled,
		"rules_path":   ys.config.RulesPath,
		"rules_loaded": ys.rules != nil,
	}

	if ys.rules != nil {
		// TODO: Get more detailed rules info from YARA
		info["status"] = "loaded"
	} else {
		info["status"] = "not_loaded"
	}

	return info
}

// LoadStaticRules load rules tĩnh trực tiếp vào code
func (ys *YaraScanner) LoadStaticRules() error {
	ys.logger.Info("Loading static YARA rules...")

	// Compile rules from static content
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	// Add static rules
	staticRules := []string{
		// Critical threats
		`rule EICAR_Static {
			meta:
				description = "EICAR Standard Anti-Virus Test File - Static"
				author = "EDR System"
				severity = 5
				threat_type = "test"
				tags = "test eicar static"
			
			strings:
				$eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
			
			condition:
				$eicar_string
		}`,

		// Simple test patterns
		`rule Simple_Test {
			meta:
				description = "Simple test pattern"
				author = "EDR System"
				severity = 2
				threat_type = "test"
				tags = "test simple"
			
			strings:
				$test = "test" nocase
			
			condition:
				$test
		}`,
	}

	rulesLoaded := 0
	for i, rule := range staticRules {
		err := compiler.AddString(rule, fmt.Sprintf("static_rule_%d", i))
		if err != nil {
			ys.logger.Error("Failed to compile static rule %d: %v", i, err)
			continue
		}
		rulesLoaded++
	}

	ys.logger.Info("Loaded %d static YARA rules", rulesLoaded)

	if rulesLoaded == 0 {
		return fmt.Errorf("no static rules loaded")
	}

	// Get compiled rules
	ys.rulesMu.Lock()
	defer ys.rulesMu.Unlock()

	ys.rules, err = compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to compile static YARA rules: %w", err)
	}

	ys.logger.Info("Static YARA rules loaded successfully")
	return nil
}

// Cleanup destroys the YARA rules and frees memory
func (ys *YaraScanner) Cleanup() {
	ys.rulesMu.Lock()
	defer ys.rulesMu.Unlock()

	if ys.rules != nil {
		ys.rules.Destroy()
		ys.rules = nil
		ys.logger.Info("YARA scanner cleanup completed")
	}
}

// GetMatchedRulesCount returns the number of loaded rules
func (ys *YaraScanner) GetMatchedRulesCount() int {
	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	if ys.rules == nil {
		return 0
	}

	// Get rules slice from the Rules object
	rules := ys.rules.GetRules()
	return len(rules)
}
