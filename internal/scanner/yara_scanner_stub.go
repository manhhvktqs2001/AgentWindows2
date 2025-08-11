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
