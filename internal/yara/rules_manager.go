package yara

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

type RulesManager struct {
	config     *config.YaraConfig
	logger     *utils.Logger
	rulesPath  string
	lastUpdate time.Time
}

type RuleInfo struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Author      string    `json:"author"`
	Date        time.Time `json:"date"`
	Tags        []string  `json:"tags"`
	Hash        string    `json:"hash"`
	Enabled     bool      `json:"enabled"`
}

type RulesStats struct {
	TotalRules    int               `json:"total_rules"`
	EnabledRules  int               `json:"enabled_rules"`
	Categories    map[string]int    `json:"categories"`
	LastUpdate    time.Time         `json:"last_update"`
	UpdateStatus  string            `json:"update_status"`
	ErrorCount    int               `json:"error_count"`
	CompileErrors []string          `json:"compile_errors"`
}

func NewRulesManager(cfg *config.YaraConfig, logger *utils.Logger) *RulesManager {
	return &RulesManager{
		config:    cfg,
		logger:    logger,
		rulesPath: cfg.RulesPath,
	}
}

// Initialize sets up the rules directory and downloads initial rules
func (rm *RulesManager) Initialize() error {
	rm.logger.Info("Initializing YARA rules manager...")
	
	// Create rules directory
	if err := os.MkdirAll(rm.rulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}
	
	// Check if rules exist
	if rm.hasRules() {
		rm.logger.Info("YARA rules already exist, skipping initial download")
		return nil
	}
	
	// Download initial rules
	return rm.DownloadRules()
}

// DownloadRules downloads YARA rules from GitHub
func (rm *RulesManager) DownloadRules() error {
	rm.logger.Info("Downloading YARA rules from GitHub...")
	
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "yara-rules-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Download ZIP file
	zipPath := filepath.Join(tempDir, "rules.zip")
	if err := rm.downloadFile(rm.config.RulesSource, zipPath); err != nil {
		return fmt.Errorf("failed to download rules: %w", err)
	}
	
	// Extract and filter rules
	if err := rm.extractAndFilterRules(zipPath); err != nil {
		return fmt.Errorf("failed to extract rules: %w", err)
	}
	
	rm.lastUpdate = time.Now()
	rm.logger.Info("YARA rules downloaded successfully")
	return nil
}

// downloadFile downloads a file from URL to local path
func (rm *RulesManager) downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()
	
	_, err = io.Copy(out, resp.Body)
	return err
}

// extractAndFilterRules extracts rules from ZIP and filters them
func (rm *RulesManager) extractAndFilterRules(zipPath string) error {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer reader.Close()
	
	// Track processed files
	processedCount := 0
	errorCount := 0
	
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		
		// Check if it's a YARA rule file
		if !strings.HasSuffix(file.Name, ".yar") && !strings.HasSuffix(file.Name, ".yara") {
			continue
		}
		
		// Skip test files and broken rules
		if rm.shouldSkipFile(file.Name) {
			continue
		}
		
		// Extract and save rule
		if err := rm.extractRule(file); err != nil {
			rm.logger.Warn("Failed to extract rule %s: %v", file.Name, err)
			errorCount++
			continue
		}
		
		processedCount++
	}
	
	rm.logger.Info("Extracted %d rules, %d errors", processedCount, errorCount)
	return nil
}

// shouldSkipFile determines if a file should be skipped
func (rm *RulesManager) shouldSkipFile(filename string) bool {
	skipPatterns := []string{
		"test", "Test", "TEST",
		"example", "Example", "EXAMPLE",
		"sample", "Sample", "SAMPLE",
		"broken", "Broken", "BROKEN",
		"deprecated", "Deprecated", "DEPRECATED",
		"old", "Old", "OLD",
		"backup", "Backup", "BACKUP",
	}
	
	filenameLower := strings.ToLower(filename)
	for _, pattern := range skipPatterns {
		if strings.Contains(filenameLower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// extractRule extracts a single rule file
func (rm *RulesManager) extractRule(file *zip.File) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	
	// Create rule file path
	rulePath := filepath.Join(rm.rulesPath, filepath.Base(file.Name))
	
	// Create output file
	out, err := os.Create(rulePath)
	if err != nil {
		return err
	}
	defer out.Close()
	
	// Copy content
	_, err = io.Copy(out, rc)
	return err
}

// hasRules checks if rules directory contains YARA rules
func (rm *RulesManager) hasRules() bool {
	files, err := os.ReadDir(rm.rulesPath)
	if err != nil {
		return false
	}
	
	for _, file := range files {
		if !file.IsDir() && (strings.HasSuffix(file.Name(), ".yar") || strings.HasSuffix(file.Name(), ".yara")) {
			return true
		}
	}
	
	return false
}

// GetRulesList returns list of available rules
func (rm *RulesManager) GetRulesList() ([]RuleInfo, error) {
	var rules []RuleInfo
	
	files, err := os.ReadDir(rm.rulesPath)
	if err != nil {
		return nil, err
	}
	
	for _, file := range files {
		if file.IsDir() || (!strings.HasSuffix(file.Name(), ".yar") && !strings.HasSuffix(file.Name(), ".yara")) {
			continue
		}
		
		ruleInfo, err := rm.parseRuleInfo(file.Name())
		if err != nil {
			rm.logger.Warn("Failed to parse rule info for %s: %v", file.Name(), err)
			continue
		}
		
		rules = append(rules, ruleInfo)
	}
	
	return rules, nil
}

// parseRuleInfo extracts metadata from YARA rule file
func (rm *RulesManager) parseRuleInfo(filename string) (RuleInfo, error) {
	ruleInfo := RuleInfo{
		Name:     filename,
		Enabled:  true,
		Category: "unknown",
	}
	
	filePath := filepath.Join(rm.rulesPath, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ruleInfo, err
	}
	
	// Calculate hash
	hash := sha256.Sum256(content)
	ruleInfo.Hash = hex.EncodeToString(hash[:])
	
	// Parse metadata from YARA rule
	ruleInfo = rm.extractMetadata(string(content), ruleInfo)
	
	return ruleInfo, nil
}

// extractMetadata extracts metadata from YARA rule content
func (rm *RulesManager) extractMetadata(content string, ruleInfo RuleInfo) RuleInfo {
	// Extract description
	descRegex := regexp.MustCompile(`description\s*=\s*"([^"]+)"`)
	if matches := descRegex.FindStringSubmatch(content); len(matches) > 1 {
		ruleInfo.Description = matches[1]
	}
	
	// Extract author
	authorRegex := regexp.MustCompile(`author\s*=\s*"([^"]+)"`)
	if matches := authorRegex.FindStringSubmatch(content); len(matches) > 1 {
		ruleInfo.Author = matches[1]
	}
	
	// Extract date
	dateRegex := regexp.MustCompile(`date\s*=\s*"([^"]+)"`)
	if matches := dateRegex.FindStringSubmatch(content); len(matches) > 1 {
		if date, err := time.Parse("2006-01-02", matches[1]); err == nil {
			ruleInfo.Date = date
		}
	}
	
	// Extract tags
	tagsRegex := regexp.MustCompile(`tags\s*=\s*"([^"]+)"`)
	if matches := tagsRegex.FindStringSubmatch(content); len(matches) > 1 {
		ruleInfo.Tags = strings.Split(matches[1], " ")
	}
	
	// Determine category from tags or filename
	ruleInfo.Category = rm.determineCategory(ruleInfo.Tags, ruleInfo.Name)
	
	return ruleInfo
}

// determineCategory determines rule category from tags or filename
func (rm *RulesManager) determineCategory(tags []string, filename string) string {
	// Check if category is in config categories
	for _, tag := range tags {
		for _, category := range rm.config.Categories {
			if strings.EqualFold(tag, category) {
				return category
			}
		}
	}
	
	// Try to determine from filename
	filenameLower := strings.ToLower(filename)
	for _, category := range rm.config.Categories {
		if strings.Contains(filenameLower, strings.ToLower(category)) {
			return category
		}
	}
	
	return "unknown"
}

// GetRulesStats returns statistics about rules
func (rm *RulesManager) GetRulesStats() RulesStats {
	stats := RulesStats{
		LastUpdate:   rm.lastUpdate,
		Categories:   make(map[string]int),
		CompileErrors: []string{},
	}
	
	rules, err := rm.GetRulesList()
	if err != nil {
		stats.UpdateStatus = "error"
		return stats
	}
	
	stats.TotalRules = len(rules)
	for _, rule := range rules {
		if rule.Enabled {
			stats.EnabledRules++
		}
		stats.Categories[rule.Category]++
	}
	
	stats.UpdateStatus = "success"
	return stats
}

// UpdateRules updates rules if needed
func (rm *RulesManager) UpdateRules() error {
	// Check if update is needed
	if rm.lastUpdate.IsZero() {
		return rm.DownloadRules()
	}
	
	// Parse update interval
	duration, err := time.ParseDuration(rm.config.UpdateInterval)
	if err != nil {
		rm.logger.Warn("Invalid update interval, using 24h: %v", err)
		duration = 24 * time.Hour
	}
	
	if time.Since(rm.lastUpdate) < duration {
		rm.logger.Debug("Rules are up to date, last update: %s", rm.lastUpdate.Format(time.RFC3339))
		return nil
	}
	
	rm.logger.Info("Updating YARA rules...")
	return rm.DownloadRules()
}

// GetRulesPath returns the path to rules directory
func (rm *RulesManager) GetRulesPath() string {
	return rm.rulesPath
}

// ValidateRule validates a YARA rule file
func (rm *RulesManager) ValidateRule(filename string) error {
	filePath := filepath.Join(rm.rulesPath, filename)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %w", err)
	}
	
	// Basic YARA syntax validation
	if !strings.Contains(string(content), "rule ") {
		return fmt.Errorf("invalid YARA rule: missing 'rule' keyword")
	}
	
	return nil
} 