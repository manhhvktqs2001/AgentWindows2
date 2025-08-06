//go:build !cgo
// +build !cgo

package scanner

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

type YaraScanner struct {
	config config.ScannerConfig
	logger *utils.Logger
}

type ScanResult struct {
	Matched  bool   `json:"matched"`
	RuleName string `json:"rule_name"`
	RuleTags string `json:"rule_tags"`
	Severity int    `json:"severity"`
	FileHash string `json:"file_hash"`
	ScanTime int64  `json:"scan_time_ms"`
}

func NewYaraScanner(config config.ScannerConfig, logger *utils.Logger) *YaraScanner {
	scanner := &YaraScanner{
		config: config,
		logger: logger,
	}

	if config.YaraEnabled {
		logger.Warn("YARA scanning is disabled (CGO not available)")
	}

	return scanner
}

func (ys *YaraScanner) LoadRules() error {
	ys.logger.Warn("YARA rules loading is disabled (CGO not available)")
	return nil
}

func (ys *YaraScanner) ScanFile(filePath string) (*ScanResult, error) {
	// Return no match when YARA is not available
	return &ScanResult{Matched: false}, nil
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Warn("YARA rules reloading is disabled (CGO not available)")
	return nil
}
