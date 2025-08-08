//go:build !cgo
// +build !cgo

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type YaraScanner struct {
	config          *config.YaraConfig
	logger          *utils.Logger
	agentID         string
	serverClient    interface{}
	responseManager interface{}
	recentAlerts    map[string]time.Time
	recentMu        sync.Mutex
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

func NewYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) *YaraScanner {
	logger.Warn("YARA Scanner: Running in stub mode (CGO disabled)")
	return &YaraScanner{
		config:       cfg,
		logger:       logger,
		recentAlerts: make(map[string]time.Time),
	}
}

// SetAgentID sets the agent ID for alert creation
func (ys *YaraScanner) SetAgentID(agentID string) {
	ys.agentID = agentID
	ys.logger.Debug("YARA Scanner Stub: Agent ID set to %s", agentID)
}

// SetServerClient sets the server client for sending alerts
func (ys *YaraScanner) SetServerClient(serverClient interface{}) {
	ys.serverClient = serverClient
	ys.logger.Debug("YARA Scanner Stub: Server client configured")
}

// SetResponseManager sets the response manager for handling threats
func (ys *YaraScanner) SetResponseManager(responseManager interface{}) {
	ys.responseManager = responseManager
	ys.logger.Debug("YARA Scanner Stub: Response manager configured")
}

func (ys *YaraScanner) LoadRules() error {
	ys.logger.Info("YARA Scanner Stub: LoadRules called (no-op)")
	return nil
}

func (ys *YaraScanner) ScanFile(filePath string) (*ScanResult, error) {
	ys.logger.Debug("YARA Scanner Stub: Scan requested for: %s", filePath)

	// Try external yara64.exe if available and rules path exists
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
				if ys.shouldSuppress(filePath, result.RuleName, 60*time.Second) {
					ys.logger.Debug("Suppressed duplicate YARA alert (external): %s | %s", filePath, result.RuleName)
					return result, nil
				}
				// Announce to console
				fmt.Fprintf(os.Stdout, "\n🚨🚨🚨 YARA THREAT DETECTED! (external) 🚨🚨🚨\n")
				fmt.Fprintf(os.Stdout, "File: %s\n", filePath)
				fmt.Fprintf(os.Stdout, "Rule: %s\n", result.RuleName)
				fmt.Fprintf(os.Stdout, "Severity: %d\n", result.Severity)
				fmt.Fprintf(os.Stdout, "Tags: %v\n", result.RuleTags)
				fmt.Fprintf(os.Stdout, "Description: %s\n", result.Description)
				fmt.Fprintf(os.Stdout, "🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")
				os.Stdout.Sync()

				// Trigger threat handling like the CGO implementation
				if fi, statErr := os.Stat(filePath); statErr == nil {
					ys.handleThreatDetection(filePath, result, fi)
				}
				return result, nil
			}
		}
	}

	// Fallback: EICAR pattern check for demo when external YARA not available
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

	contentStr := string(content)

	// Check for EICAR pattern
	if strings.Contains(contentStr, "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*") {
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

		if ys.shouldSuppress(filePath, result.RuleName, 60*time.Second) {
			ys.logger.Debug("Suppressed duplicate YARA alert (EICAR): %s | %s", filePath, result.RuleName)
			return result, nil
		}

		// Print alert directly to terminal - Force flush to ensure immediate display
		fmt.Fprintf(os.Stdout, "\n🚨🚨🚨 YARA THREAT DETECTED! 🚨🚨🚨\n")
		fmt.Fprintf(os.Stdout, "File: %s\n", filePath)
		fmt.Fprintf(os.Stdout, "Total Matches: 1\n")
		fmt.Fprintf(os.Stdout, "\nMatch 1:\n")
		fmt.Fprintf(os.Stdout, "  Rule: EICAR_Test_Stub\n")
		fmt.Fprintf(os.Stdout, "  Tags: [test eicar stub]\n")
		fmt.Fprintf(os.Stdout, "  Namespace: stub\n")
		fmt.Fprintf(os.Stdout, "\nSelected Rule: EICAR_Test_Stub\n")
		fmt.Fprintf(os.Stdout, "Severity: 5\n")
		fmt.Fprintf(os.Stdout, "Tags: [test eicar stub]\n")
		fmt.Fprintf(os.Stdout, "Description: EICAR test file detected by stub scanner\n")
		fmt.Fprintf(os.Stdout, "File Hash: stub_hash\n")
		fmt.Fprintf(os.Stdout, "File Size: %d bytes\n", len(content))
		fmt.Fprintf(os.Stdout, "Scan Time: 0ms\n")
		fmt.Fprintf(os.Stdout, "🚨🚨🚨 END ALERT 🚨🚨🚨\n\n")

		// Force flush to ensure immediate display
		os.Stdout.Sync()

		ys.logger.Warn("🚨 YARA THREAT DETECTED (STUB): %s -> Rule: EICAR_Test_Stub, Severity: 5", filePath)

		// Trigger threat handling like the CGO implementation
		if fi, statErr := os.Stat(filePath); statErr == nil {
			ys.handleThreatDetection(filePath, result, fi)
		}

		return result, nil
	}

	// Return negative result for stub
	return &ScanResult{
		Matched:       false,
		FilePath:      filePath,
		ScanTime:      time.Now().UnixMilli(),
		ScanTimestamp: time.Now(),
		Description:   "YARA scanning disabled (CGO not available)",
	}, nil
}

// scanWithExternalYara attempts to scan the file using external yara64.exe with rules in config.RulesPath
func (ys *YaraScanner) scanWithExternalYara(filePath string) (*ScanResult, bool, error) {
	yaraExe, err := exec.LookPath("yara64.exe")
	if err != nil {
		// Not available
		return nil, false, nil
	}

	// Validate rules path
	rulesPath := ys.config.RulesPath
	if rulesPath == "" {
		return nil, true, fmt.Errorf("rules_path is empty")
	}

	// Build allowed categories set from config
	allowed := make(map[string]struct{})
	for _, c := range ys.config.Categories {
		allowed[strings.ToLower(c)] = struct{}{}
	}
	// If categories empty, use a reduced default to avoid noise
	if len(allowed) == 0 {
		for _, c := range []string{"malware", "maldocs", "webshells"} {
			allowed[c] = struct{}{}
		}
	}

	// Collect .yar/.yara files under rulesPath filtered by allowed categories
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
		return nil, true, fmt.Errorf("no allowed rule files found under %s", rulesPath)
	}

	// Respect scan timeout
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
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			continue
		}

		scannerOut := bufio.NewScanner(stdout)
		var matchedRule string
		for scannerOut.Scan() {
			line := strings.TrimSpace(scannerOut.Text())
			// Expected: "RULE_NAME FILEPATH" or with -s includes strings after colon
			if line == "" {
				continue
			}
			// Take first token as rule name
			parts := strings.Fields(line)
			if len(parts) > 0 {
				matchedRule = parts[0]
				break
			}
		}
		_ = cmd.Wait()
		// Drain stderr (optional)
		if stderr != nil {
			_ = bufio.NewScanner(stderr).Err()
		}

		if matchedRule != "" {
			// Found a match
			res := &ScanResult{
				Matched:       true,
				FilePath:      filePath,
				RuleName:      matchedRule,
				RuleTags:      []string{"external"},
				Severity:      4,
				FileHash:      "",
				ScanTime:      time.Now().UnixMilli(),
				ScanTimestamp: time.Now(),
				Description:   fmt.Sprintf("Matched by external YARA rule: %s", filepath.Base(ruleFile)),
			}
			return res, true, nil
		}
	}

	return &ScanResult{Matched: false, FilePath: filePath, ScanTime: time.Now().UnixMilli(), ScanTimestamp: time.Now(), Description: "No match by external YARA"}, true, nil
}

// handleThreatDetection processes a detected threat (stub parity)
func (ys *YaraScanner) handleThreatDetection(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	// Build ThreatInfo
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

	// Send alert to server if configured
	ys.createAndSendAlert(filePath, result, fileInfo)

	// Send to Response Manager if available
	if ys.responseManager != nil {
		if rm, ok := ys.responseManager.(interface {
			HandleThreat(threat *models.ThreatInfo) error
		}); ok {
			if err := rm.HandleThreat(threat); err != nil {
				ys.logger.Error("Failed to handle threat via Response Manager (stub): %v", err)
			} else {
				ys.logger.Info("Threat sent to Response Manager for processing (stub)")
			}
		} else {
			ys.logger.Warn("Response Manager does not support HandleThreat method (stub)")
		}
	} else {
		ys.logger.Warn("Response Manager not configured - threat not processed (stub)")
	}
}

// createAndSendAlert builds alert data and sends to the server (stub parity)
func (ys *YaraScanner) createAndSendAlert(filePath string, result *ScanResult, fileInfo os.FileInfo) {
	if ys.agentID == "" || ys.serverClient == nil {
		ys.logger.Warn("Cannot send alert: agent ID or server client not set (stub)")
		return
	}

	// Đảm bảo rule_name không rỗng
	ruleName := result.RuleName
	if ruleName == "" {
		ruleName = "unknown_rule"
		ys.logger.Warn("Empty rule name, using 'unknown_rule'")
	}

	// Đảm bảo agent_id không rỗng
	if ys.agentID == "" {
		ys.logger.Warn("Cannot send alert: agent ID not set")
		return
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
	}

	if sendAlert, ok := ys.serverClient.(interface {
		SendAlert(data map[string]interface{}) error
	}); ok {
		if err := sendAlert.SendAlert(alertData); err != nil {
			ys.logger.Error("Failed to send YARA alert to server (stub): %v", err)
		} else {
			ys.logger.Info("✅ YARA alert sent to server successfully for file (stub): %s", filePath)
		}
	} else {
		ys.logger.Warn("Server client does not support SendAlert method (stub)")
	}
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Info("YARA Scanner Stub: ReloadRules called (no-op)")
	return nil
}

func (ys *YaraScanner) GetRulesInfo() map[string]interface{} {
	return map[string]interface{}{
		"enabled":      false,
		"rules_path":   ys.config.RulesPath,
		"rules_loaded": false,
		"status":       "stub_mode",
		"message":      "YARA scanning requires CGO",
	}
}

// getThreatType classifies threat type from rule tags
func (ys *YaraScanner) getThreatType(tags []string) string {
	lowerTags := make([]string, 0, len(tags))
	for _, t := range tags {
		lowerTags = append(lowerTags, strings.ToLower(t))
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
	default:
		return "malware"
	}
}

// shouldSuppress returns true if an alert for the same file and rule occurred within window
func (ys *YaraScanner) shouldSuppress(filePath, rule string, window time.Duration) bool {
	key := filePath + "|" + rule
	ys.recentMu.Lock()
	defer ys.recentMu.Unlock()
	if last, ok := ys.recentAlerts[key]; ok {
		if time.Since(last) < window {
			return true
		}
	}
	ys.recentAlerts[key] = time.Now()
	return false
}
