//go:build !cgo
// +build !cgo

package scanner

import (
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

type YaraScanner struct {
	config          *config.YaraConfig
	logger          *utils.Logger
	agentID         string
	serverClient    interface{}
	responseManager interface{}
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
		config: cfg,
		logger: logger,
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

	// Return negative result for stub
	return &ScanResult{
		Matched:       false,
		FilePath:      filePath,
		ScanTime:      time.Now().UnixMilli(),
		ScanTimestamp: time.Now(),
		Description:   "YARA scanning disabled (CGO not available)",
	}, nil
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
