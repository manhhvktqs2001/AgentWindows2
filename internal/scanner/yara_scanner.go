//go:build cgo
// +build cgo

package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"

	"github.com/hillu/go-yara/v4"
)

type YaraScanner struct {
	config  config.ScannerConfig
	logger  *utils.Logger
	rules   *yara.Rules
	rulesMu sync.RWMutex
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

	// Load YARA rules
	if config.YaraEnabled {
		err := scanner.LoadRules()
		if err != nil {
			logger.Error("Failed to load YARA rules: %v", err)
		}
	}

	return scanner
}

func (ys *YaraScanner) LoadRules() error {
	ys.logger.Info("Loading YARA rules from: %s", ys.config.YaraRulesPath)

	// Check if rules directory exists
	if _, err := os.Stat(ys.config.YaraRulesPath); os.IsNotExist(err) {
		ys.logger.Warn("YARA rules directory does not exist: %s", ys.config.YaraRulesPath)
		return nil
	}

	// Compile rules from directory
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	// Walk through rules directory
	err = filepath.Walk(ys.config.YaraRulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YARA files
		if info.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yar" && ext != ".yara" {
			return nil
		}

		// Add rule file to compiler
		ruleFile, err := os.Open(path)
		if err != nil {
			ys.logger.Error("Failed to open rule file %s: %v", path, err)
			return nil
		}
		defer ruleFile.Close()

		err = compiler.AddFile(ruleFile, "")
		if err != nil {
			ys.logger.Error("Failed to add rule file %s: %v", path, err)
			return nil
		}

		ys.logger.Debug("Added YARA rule file: %s", path)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk rules directory: %w", err)
	}

	// Get compiled rules
	ys.rulesMu.Lock()
	defer ys.rulesMu.Unlock()

	ys.rules, err = compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to compile YARA rules: %w", err)
	}

	ys.logger.Info("YARA rules loaded successfully")
	return nil
}

func (ys *YaraScanner) ScanFile(filePath string) (*ScanResult, error) {
	if !ys.config.YaraEnabled || ys.rules == nil {
		return &ScanResult{Matched: false}, nil
	}

	ys.rulesMu.RLock()
	defer ys.rulesMu.RUnlock()

	// Open file for scanning
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file for scanning: %w", err)
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Check file size limit (default 100MB)
	maxSize := int64(100 * 1024 * 1024) // 100MB default
	if fileInfo.Size() > maxSize {
		ys.logger.Debug("File too large for scanning: %s (%d bytes)", filePath, fileInfo.Size())
		return &ScanResult{Matched: false}, nil
	}

	// Scan file
	matches, err := ys.rules.ScanFile(file, 0, ys.config.ScanTimeout*1000)
	if err != nil {
		return nil, fmt.Errorf("YARA scan failed: %w", err)
	}

	result := &ScanResult{
		Matched:  len(matches) > 0,
		FileHash: ys.calculateFileHash(filePath),
	}

	if result.Matched {
		// Get first match details
		match := matches[0]
		result.RuleName = match.Rule
		result.RuleTags = match.Tags
		result.Severity = ys.getRuleSeverity(match.Rule)

		ys.logger.Warn("YARA rule matched: %s -> %s", filePath, match.Rule)
	}

	return result, nil
}

func (ys *YaraScanner) calculateFileHash(filePath string) string {
	// TODO: Implement file hash calculation (MD5, SHA256)
	return ""
}

func (ys *YaraScanner) getRuleSeverity(ruleName string) int {
	// TODO: Implement severity mapping based on rule name or tags
	return 3 // Default medium severity
}

func (ys *YaraScanner) ReloadRules() error {
	ys.logger.Info("Reloading YARA rules...")
	return ys.LoadRules()
}
