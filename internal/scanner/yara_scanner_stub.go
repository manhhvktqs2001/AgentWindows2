package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"edr-agent-windows/internal/communication"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/response"
	"edr-agent-windows/internal/utils"
)

// YaraScanner implements YARA-based file scanning using external yara64.exe
type YaraScanner struct {
	config           *config.YaraConfig
	logger           *utils.Logger
	serverClient     *communication.ServerClient
	responseManager  *response.ResponseManager
	notificationCtrl *response.NotificationController
	yaraExePath      string
	rulesPath        string
	agentID          string
	masterRulePath   string
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
func (ys *YaraScanner) SetNotificationController(ctrl *response.NotificationController) {
	ys.notificationCtrl = ctrl
}

func (ys *YaraScanner) LoadRules() error {
	if !ys.config.Enabled {
		return nil
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
	// Build a master rule file that includes all selected .yar files
	ruleFiles, err := ys.collectRuleFiles()
	if err != nil {
		return err
	}
	if len(ruleFiles) == 0 {
		return fmt.Errorf("no YARA rule files found under %s", ys.rulesPath)
	}

	masterPath, err := ys.writeMasterIncludeFile(ruleFiles)
	if err != nil {
		return fmt.Errorf("failed to write master rule file: %w", err)
	}
	ys.masterRulePath = masterPath

	ys.logger.Info("YARA: external scanner ready (rules: %s, files: %d)", ys.rulesPath, len(ruleFiles))
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

	// Use master include file so YARA loads all rules at once
	ruleFile := ys.masterRulePath
	if ruleFile == "" {
		// Fallback: use rulesPath directly (may fail if directory); still try
		ruleFile = ys.rulesPath
	}
	args := []string{"-w", ruleFile, filePath}

	ys.logger.Debug("🔍 YARA scanning file: %s with rules: %s", filePath, ruleFile)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ys.config.ScanTimeout)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ys.yaraExePath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			ys.logger.Warn("YARA scan timeout for file: %s", filePath)
			return nil, fmt.Errorf("scan timeout")
		}
		ys.logger.Debug("YARA scan completed for file: %s (exit code: %v, stderr: %s)", filePath, err, stderr.String())
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		ys.logger.Debug("YARA scan: no matches found for file: %s", filePath)
		return nil, nil
	}

	ys.logger.Info("🚨 YARA THREAT DETECTED in file: %s", filePath)
	ys.logger.Info("YARA output: %s", out)

	lines := strings.Split(out, "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		ys.logger.Warn("Unexpected YARA output format: %s", out)
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

	ys.logger.Info("🚨 THREAT DETECTED - Rule: %s, Severity: %d, File: %s", ruleName, threat.Severity, filePath)

	// Hand off to ResponseManager for notifications and actions
	if ys.responseManager != nil {
		_ = ys.responseManager.HandleThreat(threat)
	}

	// Show Windows notification if notification controller is available
	if ys.notificationCtrl != nil {
		if err := ys.notificationCtrl.SendNotification(threat, threat.Severity); err != nil {
			ys.logger.Warn("Failed to send notification: %v", err)
		} else {
			ys.logger.Info("🚨 THREAT DETECTED - Windows notification sent: %s", threat.ThreatName)
		}
	}

	// Send alert to server
	ys.sendAlert(threat)
	return threat, nil
}

func (ys *YaraScanner) sendAlert(t *models.ThreatInfo) {
	if ys.serverClient == nil {
		ys.logger.Warn("Server client not available, cannot send alert")
		return
	}
	payload := map[string]interface{}{
		"agent_id":    ys.serverClient.GetAgentID(),
		"event_type":  "alert",
		"timestamp":   time.Now().UTC(),
		"threat_info": t,
	}

	ys.logger.Info("📤 Sending threat alert to server: %s (severity: %d)", t.ThreatName, t.Severity)

	if err := ys.serverClient.SendAlert(payload); err != nil {
		ys.logger.Error("Failed to send alert to server: %v", err)
	} else {
		ys.logger.Info("✅ Threat alert sent to server successfully")
	}
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
	if strings.Contains(l, "eicar") {
		return 5
	}
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

// collectRuleFiles walks rulesPath and returns all .yar files filtered by categories (if configured)
func (ys *YaraScanner) collectRuleFiles() ([]string, error) {
	var files []string
	var categorySet map[string]struct{}

	if len(ys.config.Categories) > 0 {
		categorySet = make(map[string]struct{}, len(ys.config.Categories))
		for _, c := range ys.config.Categories {
			lc := strings.ToLower(strings.TrimSpace(c))
			if lc != "" {
				categorySet[lc] = struct{}{}
			}
		}
	}

	walkFn := func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d == nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(path), ".yar") {
			if categorySet != nil {
				// Check if file is under a selected category subfolder
				rel, _ := filepath.Rel(ys.rulesPath, path)
				parts := strings.Split(rel, string(os.PathSeparator))
				if len(parts) > 0 {
					first := strings.ToLower(parts[0])
					if _, ok := categorySet[first]; !ok {
						return nil
					}
				}
			}
			files = append(files, path)
		}
		return nil
	}

	_ = filepath.WalkDir(ys.rulesPath, walkFn)
	return files, nil
}

// writeMasterIncludeFile writes a master YARA file that includes all provided rule files
func (ys *YaraScanner) writeMasterIncludeFile(ruleFiles []string) (string, error) {
	cacheDir := "yara-cache"
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", err
	}
	master := filepath.Join(cacheDir, "master_rules.yar")
	var b bytes.Buffer
	// Add a header comment
	b.WriteString("// Auto-generated master YARA includes\n")
	for _, rf := range ruleFiles {
		// Escape backslashes for YARA include string
		esc := strings.ReplaceAll(rf, "\\", "\\\\")
		b.WriteString("include \"" + esc + "\"\n")
	}
	if err := os.WriteFile(master, b.Bytes(), 0644); err != nil {
		return "", err
	}
	return master, nil
}
