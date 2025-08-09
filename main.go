package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"edr-agent-windows/internal/agent"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/response"
	"edr-agent-windows/internal/service"
	"edr-agent-windows/internal/utils"

	"io"
	"net/http"
	"sort"

	"encoding/json"
	"net"

	"golang.org/x/sys/windows"

	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/scanner"
	"reflect"
)

var (
	Version   = "1.0.0"
	BuildTime = "2025-08-06"
)

// checkAdminPrivileges checks if the process is running with administrator privileges
func checkAdminPrivileges() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// requestAdminPrivileges restarts the process with administrator privileges
func requestAdminPrivileges() error {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := os.Args[1:]

	// Check if we're running from go run (temporary executable)
	if strings.Contains(exe, "go-build") || strings.Contains(exe, "Temp") {
		fmt.Println("⚠️  Detected go run mode - building executable first...")

		// Build the executable
		buildCmd := exec.Command("go", "build", "-o", "edr-agent.exe", ".")
		buildCmd.Dir = cwd
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr

		if err := buildCmd.Run(); err != nil {
			return fmt.Errorf("failed to build executable: %w", err)
		}

		// Use the built executable
		exe = filepath.Join(cwd, "edr-agent.exe")
	}

	verbPtr, _ := windows.UTF16PtrFromString(verb)
	exePtr, _ := windows.UTF16PtrFromString(exe)
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)
	argPtr, _ := windows.UTF16PtrFromString(strings.Join(args, " "))

	var showCmd int32 = 1 //SW_NORMAL

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		return fmt.Errorf("failed to restart with admin privileges: %w", err)
	}
	return nil
}

func main() {
	// Check if running with administrator privileges
	if !checkAdminPrivileges() {
		fmt.Println("⚠️  EDR Agent requires administrator privileges to monitor system activities")
		fmt.Println("🔄 Restarting with administrator privileges...")

		if err := requestAdminPrivileges(); err != nil {
			fmt.Printf("❌ Failed to restart with admin privileges: %v\n", err)
			fmt.Println("💡 Please run this application as Administrator")
			os.Exit(1)
		}

		// Exit current process
		os.Exit(0)
	}

	fmt.Println("✅ Running with administrator privileges")

	// Parse command line flags
	var (
		install          = flag.Bool("install", false, "Install as Windows service")
		uninstall        = flag.Bool("uninstall", false, "Uninstall Windows service")
		start            = flag.Bool("start", false, "Start Windows service")
		stop             = flag.Bool("stop", false, "Stop Windows service")
		status           = flag.Bool("status", false, "Check service status")
		configPath       = flag.String("config", "config.yaml", "Path to configuration file")
		version          = flag.Bool("version", false, "Show version information")
		reset            = flag.Bool("reset", false, "Reset agent registration (force new registration)")
		updateRules      = flag.Bool("update-rules", false, "Update YARA rules")
		report           = flag.Bool("report", false, "Generate system report")
		testYara         = flag.String("test-yara", "", "Test YARA scanning on specific file")
		console          = flag.Bool("console", false, "Run in console mode (not as service)")
		testNotification = flag.Bool("test-notification", false, "Test notification system")
		testAlert        = flag.Bool("test-alert", false, "Test security alert notification")
	)
	flag.Parse()

	// Show version
	if *version {
		fmt.Printf("EDR Agent Windows v%s\n", Version)
		fmt.Printf("Build Time: %s\n", BuildTime)
		fmt.Printf("Go Version: %s\n", runtime.Version())
		fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	// Service management
	if *install {
		if err := service.Install(); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("✅ EDR Agent service installed successfully")
		return
	}

	if *uninstall {
		if err := service.Uninstall(); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("✅ EDR Agent service uninstalled successfully")
		return
	}

	if *start {
		if err := service.Start(); err != nil {
			log.Fatalf("Failed to start service: %v", err)
		}
		fmt.Println("✅ EDR Agent service started successfully")
		return
	}

	if *stop {
		if err := service.Stop(); err != nil {
			log.Fatalf("Failed to stop service: %v", err)
		}
		fmt.Println("✅ EDR Agent service stopped successfully")
		return
	}

	if *status {
		status, err := service.Status()
		if err != nil {
			log.Fatalf("Failed to get service status: %v", err)
		}
		fmt.Printf("Service status: %s\n", status)
		return
	}

	// Reset agent registration
	if *reset {
		if err := resetAgentRegistration(*configPath); err != nil {
			log.Fatalf("Failed to reset agent registration: %v", err)
		}
		fmt.Println("✅ Agent registration reset successfully")
		return
	}

	// Update YARA rules
	if *updateRules {
		if err := updateYaraRules(*configPath); err != nil {
			log.Fatalf("Failed to update YARA rules: %v", err)
		}
		fmt.Println("✅ YARA rules updated successfully")
		return
	}

	// Generate system report
	if *report {
		if err := generateSystemReport(*configPath); err != nil {
			log.Fatalf("Failed to generate system report: %v", err)
		}
		fmt.Println("✅ System report generated successfully")
		return
	}

	// Test notification system
	if *testNotification {
		testNotificationSystem(*configPath)
		return
	}

	// Test security alert
	if *testAlert {
		testSecurityAlert(*configPath)
		return
	}

	// Load configuration
	fmt.Printf("📋 Loading configuration from: %s\n", *configPath)
	cfg, err := config.LoadOrCreate(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Validate and fix configuration
	config.ValidateAndFix(cfg)

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)
	defer logger.Close()

	// Test YARA functionality if requested
	if *testYara != "" {
		testYaraScanning(*testYara, cfg, logger)
		return
	}

	// Log startup information
	logger.Info("=== EDR Agent Windows Starting ===")
	logger.Info("Version: %s", Version)
	logger.Info("Build Time: %s", BuildTime)
	logger.Info("Config Path: %s", *configPath)
	logger.Info("Agent Name: %s", cfg.Agent.Name)
	logger.Info("Server URL: %s", cfg.Server.URL)
	logger.Info("Monitoring Enabled:")
	logger.Info("  - File System: %v", cfg.Monitoring.FileSystem.Enabled)
	logger.Info("  - Processes: %v", cfg.Monitoring.Processes.Enabled)
	logger.Info("  - Network: %v", cfg.Monitoring.Network.Enabled)
	logger.Info("  - Registry: %v", cfg.Monitoring.Registry.Enabled)
	logger.Info("YARA Enabled: %v", cfg.Yara.Enabled)

	// Show loaded YARA rules
	rules, err := filepath.Glob(filepath.Join(cfg.Yara.RulesPath, "**/*.yar"))
	if err != nil {
		// Fallback to simple glob if recursive not supported
		rules, err = filepath.Glob(filepath.Join(cfg.Yara.RulesPath, "*.yar"))
		if err != nil {
			logger.Error("Failed to list YARA rules: %v", err)
			fmt.Printf("Failed to list YARA rules: %v\n", err)
		}
	}
	if err == nil {
		// Sort rules for better display
		sort.Slice(rules, func(i, j int) bool {
			return rules[i] < rules[j]
		})

		logger.Info("Loaded %d YARA rule files:", len(rules))
		fmt.Printf("\n=== Loaded %d YARA rule files ===\n", len(rules))
		for i, rule := range rules {
			// Get relative path from rules directory
			relPath, _ := filepath.Rel(cfg.Yara.RulesPath, rule)
			content, _ := os.ReadFile(rule)
			logger.Info("   %d. %s (%d bytes)", i+1, relPath, len(content))
			fmt.Printf("   %d. %s (%d bytes)\n", i+1, relPath, len(content))
		}
		fmt.Println("")
	}

	// Create agent
	agentInstance, err := agent.NewAgent(cfg, logger)
	if err != nil {
		logger.Error("Failed to create agent: %v", err)
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Determine run mode
	if service.IsRunningAsService() && !*console {
		// Run as Windows service
		logger.Info("🔧 Running as Windows service")
		if err := service.Run(agentInstance); err != nil {
			logger.Error("Service failed: %v", err)
			os.Exit(1)
		}
	} else {
		// Run in console mode
		logger.Info("💻 Running in console mode")

		// Start agent
		if err := agentInstance.Start(); err != nil {
			logger.Error("Failed to start agent: %v", err)
			log.Fatalf("Failed to start agent: %v", err)
		}

		logger.Info("✅ EDR Agent started successfully")
		logger.Info("Press Ctrl+C to stop")

		// Wait for interrupt signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("Shutting down...")
		agentInstance.Stop()
		logger.Info("✅ EDR Agent stopped")
	}
}

// testNotificationSystem tests the notification system
func testNotificationSystem(configPath string) {
	fmt.Println("🧪 Testing EDR Notification System...")

	// Load config
	cfg, err := config.LoadOrCreate(configPath)
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)
	defer logger.Close()

	fmt.Println("📢 Testing Windows Toast Notifier...")

	// Create notification content
	content := &response.NotificationContent{
		Title:     "🧪 EDR Test Notification",
		Message:   "This is a test notification from EDR Agent. The notification system is working correctly and can display security alerts when threats are detected.",
		Severity:  4,
		Timestamp: time.Now(),
	}

	// Create toast notifier
	toastNotifier := response.NewWindowsToastNotifier(&cfg.Response, logger)
	if err := toastNotifier.Start(); err != nil {
		fmt.Printf("❌ Failed to start toast notifier: %v\n", err)
		return
	}

	// Send test notification
	err = toastNotifier.SendNotification(content)
	if err != nil {
		fmt.Printf("❌ Notification test failed: %v\n", err)
	} else {
		fmt.Printf("✅ Notification test completed successfully\n")
		fmt.Printf("💡 You should see a test notification on your screen\n")
	}

	time.Sleep(3 * time.Second)
	fmt.Println("🏁 Notification test completed")
}

// testSecurityAlert tests security alert notification
func testSecurityAlert(configPath string) {
	fmt.Println("🚨 Testing Security Alert Notification...")

	// Load config
	cfg, err := config.LoadOrCreate(configPath)
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)
	defer logger.Close()

	// Create security alert content
	content := &response.NotificationContent{
		Title:     "🚨 SECURITY ALERT - Threat Detected",
		Message:   "CRITICAL: YARA rule 'malware_detection' has identified a suspicious file at C:\\temp\\suspicious.exe. Threat level: HIGH. Immediate action recommended. File has been automatically quarantined for safety.",
		Severity:  5,
		Timestamp: time.Now(),
		ThreatInfo: &models.ThreatInfo{
			ThreatName:  "test_malware_detection",
			FilePath:    "C:\\temp\\suspicious.exe",
			Description: "Test malware detection alert",
		},
	}

	// Create toast notifier
	toastNotifier := response.NewWindowsToastNotifier(&cfg.Response, logger)
	if err := toastNotifier.Start(); err != nil {
		fmt.Printf("❌ Failed to start toast notifier: %v\n", err)
		return
	}

	// Send security alert
	err = toastNotifier.SendNotification(content)
	if err != nil {
		fmt.Printf("❌ Security alert test failed: %v\n", err)
	} else {
		fmt.Printf("✅ Security alert test completed successfully\n")
		fmt.Printf("💡 You should see a critical security alert on your screen\n")
	}

	time.Sleep(5 * time.Second)
	fmt.Println("🏁 Security alert test completed")
}

// testYaraScanning tests YARA scanning functionality
func testYaraScanning(filePath string, cfg *config.Config, logger *utils.Logger) {
	fmt.Fprintf(os.Stdout, "🔍 Testing YARA scanning on: %s\n", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stdout, "❌ File not found: %s\n", filePath)
		return
	}

	// Create YARA scanner
	scanner := createYaraScanner(cfg, logger)

	// Scan file
	if s, ok := scanner.(interface {
		ScanFile(string) (interface{}, error)
	}); ok {
		result, err := s.ScanFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stdout, "❌ Scan failed: %v\n", err)
			return
		}

		// Use reflection to access the result fields
		v := reflect.ValueOf(result)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}

		// Display results
		fmt.Fprintf(os.Stdout, "\n=== YARA Scan Results ===\n")

		// Get FilePath
		if filePathField := v.FieldByName("FilePath"); filePathField.IsValid() {
			fmt.Fprintf(os.Stdout, "File: %s\n", filePathField.Interface())
		}

		// Get Matched
		if matchedField := v.FieldByName("Matched"); matchedField.IsValid() {
			matched := matchedField.Interface().(bool)
			fmt.Fprintf(os.Stdout, "Matched: %v\n", matched)

			if matched {
				fmt.Fprintf(os.Stdout, "🚨 THREAT DETECTED!\n")

				// Get RuleName
				if ruleNameField := v.FieldByName("RuleName"); ruleNameField.IsValid() {
					fmt.Fprintf(os.Stdout, "Rule: %s\n", ruleNameField.Interface())
				}

				// Get Severity
				if severityField := v.FieldByName("Severity"); severityField.IsValid() {
					fmt.Fprintf(os.Stdout, "Severity: %d\n", severityField.Interface())
				}

				// Get RuleTags
				if ruleTagsField := v.FieldByName("RuleTags"); ruleTagsField.IsValid() {
					fmt.Fprintf(os.Stdout, "Tags: %v\n", ruleTagsField.Interface())
				}

				// Get Description
				if descriptionField := v.FieldByName("Description"); descriptionField.IsValid() {
					fmt.Fprintf(os.Stdout, "Description: %s\n", descriptionField.Interface())
				}

				// Get FileHash
				if fileHashField := v.FieldByName("FileHash"); fileHashField.IsValid() {
					fmt.Fprintf(os.Stdout, "File Hash: %s\n", fileHashField.Interface())
				}
			} else {
				fmt.Fprintf(os.Stdout, "✅ File is clean\n")
			}

			// Get ScanTime
			if scanTimeField := v.FieldByName("ScanTime"); scanTimeField.IsValid() {
				fmt.Fprintf(os.Stdout, "Scan Time: %dms\n", scanTimeField.Interface())
			}

			// Get FileSize
			if fileSizeField := v.FieldByName("FileSize"); fileSizeField.IsValid() {
				fmt.Fprintf(os.Stdout, "File Size: %d bytes\n", fileSizeField.Interface())
			}
		}

		// Force flush to ensure immediate display
		os.Stdout.Sync()
	} else {
		fmt.Fprintf(os.Stdout, "❌ Scanner does not support ScanFile method\n")
	}
}

// createYaraScanner creates and configures YARA scanner for testing
func createYaraScanner(cfg *config.Config, logger *utils.Logger) interface{} {
	// Import scanner package functions
	scanner := scanner.NewYaraScanner(&cfg.Yara, logger)

	// Load rules
	if err := scanner.LoadRules(); err != nil {
		logger.Error("Failed to load YARA rules: %v", err)
		fmt.Printf("⚠️  Warning: Failed to load YARA rules: %v\n", err)
		fmt.Printf("Creating test rules...\n")
		createTestRules(cfg.Yara.RulesPath)
		scanner.LoadRules()
	}

	return scanner
}

// createTestRules creates test rules for demonstration
func createTestRules(rulesPath string) {
	// Create rules directory
	if err := os.MkdirAll(rulesPath, 0755); err != nil {
		fmt.Printf("Failed to create rules directory: %v\n", err)
		return
	}

	// Create test malware file for demonstration
	testFile := "test_malware.txt"
	testContent := "This is a test malware file for EDR testing"

	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		fmt.Printf("Failed to create test file: %v\n", err)
	} else {
		fmt.Printf("📁 Created test file: %s\n", testFile)
		fmt.Printf("💡 You can test with: go run main.go -test-yara %s\n", testFile)
	}

	// Create EICAR test file
	eicarContent := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	eicarFile := "eicar_test.txt"

	if err := os.WriteFile(eicarFile, []byte(eicarContent), 0644); err != nil {
		fmt.Printf("Failed to create EICAR test file: %v\n", err)
	} else {
		fmt.Printf("📁 Created EICAR test file: %s\n", eicarFile)
		fmt.Printf("💡 You can test with: go run main.go -test-yara %s\n", eicarFile)
	}

	fmt.Printf("✅ Test files created successfully\n")
}

// Helper functions to work with scanner interface
func newYaraScanner(cfg *config.YaraConfig, logger *utils.Logger) interface{} {
	// This would call the actual scanner.NewYaraScanner
	// For now, return a placeholder
	return &yaraTestScanner{cfg: cfg, logger: logger}
}

func loadRules(scanner interface{}) error {
	if s, ok := scanner.(interface{ LoadRules() error }); ok {
		return s.LoadRules()
	}
	return fmt.Errorf("scanner does not support LoadRules")
}

// Temporary scanner interface for testing
type yaraTestScanner struct {
	cfg    *config.YaraConfig
	logger *utils.Logger
}

func (s *yaraTestScanner) LoadRules() error {
	s.logger.Info("Loading YARA rules from: %s", s.cfg.RulesPath)

	// List all rules in the directory and subdirectories
	rules, err := filepath.Glob(filepath.Join(s.cfg.RulesPath, "**/*.yar"))
	if err != nil {
		// Fallback to simple glob if recursive not supported
		rules, err = filepath.Glob(filepath.Join(s.cfg.RulesPath, "*.yar"))
		if err != nil {
			return fmt.Errorf("failed to list rules: %w", err)
		}
	}

	s.logger.Info("Found %d YARA rule files", len(rules))
	for i, rule := range rules {
		relPath, _ := filepath.Rel(s.cfg.RulesPath, rule)
		content, _ := os.ReadFile(rule)
		s.logger.Info("Rule %d: %s (%d bytes)", i+1, relPath, len(content))
	}

	return nil
}

func (s *yaraTestScanner) ScanFile(filePath string) (*scanner.ScanResult, error) {
	// Read the file to scan
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	result := &scanner.ScanResult{
		FilePath: filePath,
		Matched:  false,
		FileSize: int64(len(content)),
		ScanTime: time.Now().UnixMilli(),
	}

	contentStr := string(content)

	// Load and parse YARA rules from all subdirectories
	rules, err := filepath.Glob(filepath.Join(s.cfg.RulesPath, "**/*.yar"))
	if err != nil {
		// Fallback to simple glob if recursive not supported
		rules, err = filepath.Glob(filepath.Join(s.cfg.RulesPath, "*.yar"))
		if err != nil {
			return nil, fmt.Errorf("failed to list rules: %w", err)
		}
	}

	s.logger.Info("Scanning file %s against %d YARA rules", filePath, len(rules))

	// Simple rule parsing and matching
	for _, rulePath := range rules {
		ruleContent, err := os.ReadFile(rulePath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(ruleContent), "\n")

		// Extract rule name and patterns
		var ruleDisplayName string
		var patterns []string

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "rule ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					ruleDisplayName = parts[1]
				}
			} else if strings.Contains(line, "$") && strings.Contains(line, "=") {
				// Extract string pattern
				if strings.Contains(line, "=") {
					parts := strings.Split(line, "=")
					if len(parts) >= 2 {
						pattern := strings.Trim(strings.TrimSpace(parts[1]), `"`)
						patterns = append(patterns, pattern)
					}
				}
			}
		}

		// Check if any pattern matches
		for _, pattern := range patterns {
			if contains(contentStr, pattern) {
				result.Matched = true
				result.RuleName = ruleDisplayName
				result.Severity = 4 // High severity for matched rules
				result.Description = fmt.Sprintf("Pattern '%s' matched in rule %s", pattern, ruleDisplayName)
				result.RuleTags = []string{"yara", "detection"}

				s.logger.Info("🚨 THREAT DETECTED! Rule: %s, Pattern: %s", ruleDisplayName, pattern)
				return result, nil
			}
		}
	}

	if !result.Matched {
		s.logger.Info("✅ File is clean - no YARA rule matches")
	}

	return result, nil
}

type scanResult struct {
	FilePath    string   `json:"file_path"`
	Matched     bool     `json:"matched"`
	RuleName    string   `json:"rule_name"`
	Severity    int      `json:"severity"`
	Description string   `json:"description"`
	RuleTags    []string `json:"rule_tags"`
	FileHash    string   `json:"file_hash"`
	FileSize    int64    `json:"file_size"`
	ScanTime    int64    `json:"scan_time_ms"`
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// resetAgentRegistration clears agent registration to force re-registration
func resetAgentRegistration(configPath string) error {
	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Clear agent ID to force re-registration
	cfg.Agent.ID = ""

	// Save updated config
	err = config.SaveWithBackup(cfg, configPath)
	if err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("🔄 Agent ID cleared from config")
	fmt.Println("🆕 Agent will register as new on next start")
	return nil
}

func checkInternetConnection() bool {
	conn, err := net.DialTimeout("tcp", "github.com:80", 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// getYaraFilesFromGitHubAPI lấy danh sách file .yar trong 1 category từ GitHub API, trả về Name và DownloadURL
func getYaraFilesFromGitHubAPI(category string) ([]struct{ Name, DownloadURL string }, error) {
	apiURL := "https://api.github.com/repos/Yara-Rules/rules/contents/" + category
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var files []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		DownloadURL string `json:"download_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, err
	}
	var yarFiles []struct{ Name, DownloadURL string }
	for _, f := range files {
		if f.Type == "file" && strings.HasSuffix(f.Name, ".yar") && f.DownloadURL != "" {
			yarFiles = append(yarFiles, struct{ Name, DownloadURL string }{f.Name, f.DownloadURL})
		}
	}
	return yarFiles, nil
}

func updateYaraRules(configPath string) error {
	// Check Internet connection first
	if !checkInternetConnection() {
		fmt.Println("❌ Không có kết nối Internet. Không thể cập nhật YARA rules!")
		return fmt.Errorf("no internet connection")
	}

	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger (for future use)
	_ = utils.NewLogger(&cfg.Log)

	fmt.Println("🔄 YARA rules update initiated")
	fmt.Printf("📁 Rules path: %s\n", cfg.Yara.RulesPath)

	// Create rules directory if it doesn't exist
	if err := os.MkdirAll(cfg.Yara.RulesPath, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	categories := cfg.Yara.Categories
	if len(categories) == 0 {
		categories = []string{"malware", "backdoor", "trojan", "ransomware"}
		fmt.Println("⚠️  No categories specified in config, using defaults")
	}
	fmt.Printf("📋 Selected categories: %v\n", categories)
	totalDownloaded := 0
	for _, category := range categories {
		fmt.Printf("\n📥 Downloading %s rules...\n", category)
		files, err := getYaraFilesFromGitHubAPI(category)
		if err != nil {
			fmt.Printf("❌ Failed to get file list from GitHub API for %s: %v\n", category, err)
			continue
		}
		categoryDir := filepath.Join(cfg.Yara.RulesPath, category)
		if err := os.MkdirAll(categoryDir, 0755); err != nil {
			fmt.Printf("❌ Failed to create category dir %s: %v\n", categoryDir, err)
			continue
		}
		for _, file := range files {
			outputPath := filepath.Join(categoryDir, file.Name)
			if _, err := os.Stat(outputPath); err == nil {
				fmt.Printf("   ⏩ Đã có: %s, bỏ qua tải lại\n", filepath.Join(category, file.Name))
				continue
			}
			content, err := downloadGitHubFile(file.DownloadURL)
			if err != nil {
				fmt.Printf("❌ Failed to download %s: %v\n", filepath.Join(category, file.Name), err)
				continue
			}
			if err := os.WriteFile(outputPath, content, 0644); err != nil {
				fmt.Printf("❌ Failed to save %s: %v\n", filepath.Join(category, file.Name), err)
				continue
			}
			fmt.Printf("   ✅ Downloaded: %s (%d bytes)\n", filepath.Join(category, file.Name), len(content))
			totalDownloaded++
		}
	}
	fmt.Printf("\n✅ Successfully downloaded %d YARA rule files\n", totalDownloaded)
	// List all downloaded rules (recursive)
	fmt.Println("\n📋 YARA Rules loaded:")
	rules, err := filepath.Glob(filepath.Join(cfg.Yara.RulesPath, "**/*.yar"))
	if err != nil {
		// Fallback to simple glob if recursive not supported
		rules, err = filepath.Glob(filepath.Join(cfg.Yara.RulesPath, "*.yar"))
		if err != nil {
			return fmt.Errorf("failed to list rules: %w", err)
		}
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i] < rules[j]
	})
	for i, rule := range rules {
		relPath, _ := filepath.Rel(cfg.Yara.RulesPath, rule)
		content, _ := os.ReadFile(rule)
		fmt.Printf("   %d. %s (%d bytes)\n", i+1, relPath, len(content))
	}
	fmt.Printf("\n✅ Successfully loaded %d YARA rules\n", len(rules))
	fmt.Println("🎯 Rules are ready for testing!")
	fmt.Println("💡 Test with: edr-agent.exe -test-yara <yourfile>")
	return nil
}

// downloadGitHubFile downloads a file from GitHub
func downloadGitHubFile(fileURL string) ([]byte, error) {
	resp, err := http.Get(fileURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, fileURL)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return content, nil
}

// generateSystemReport generates a comprehensive system report
func generateSystemReport(configPath string) error {
	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)

	logger.Info("Generating system report...")

	// TODO: Implement system report generation
	fmt.Println("📊 Generating system report...")
	fmt.Println("📋 Agent Configuration:")
	fmt.Printf("   - Agent Name: %s\n", cfg.Agent.Name)
	fmt.Printf("   - Server URL: %s\n", cfg.Server.URL)
	fmt.Printf("   - Heartbeat Interval: %d seconds\n", cfg.Agent.HeartbeatInterval)
	fmt.Println("📈 Monitoring Status:")
	fmt.Printf("   - File System: %v\n", cfg.Monitoring.FileSystem.Enabled)
	fmt.Printf("   - Processes: %v\n", cfg.Monitoring.Processes.Enabled)
	fmt.Printf("   - Network: %v\n", cfg.Monitoring.Network.Enabled)
	fmt.Printf("   - Registry: %v\n", cfg.Monitoring.Registry.Enabled)
	fmt.Println("🔍 YARA Configuration:")
	fmt.Printf("   - Enabled: %v\n", cfg.Yara.Enabled)
	fmt.Printf("   - Auto Update: %v\n", cfg.Yara.AutoUpdate)
	fmt.Printf("   - Update Interval: %s\n", cfg.Yara.UpdateInterval)
	fmt.Printf("   - Rules Path: %s\n", cfg.Yara.RulesPath)
	fmt.Println("✅ System report generated successfully")

	return nil
}
