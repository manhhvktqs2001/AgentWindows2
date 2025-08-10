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
	fmt.Printf("🔍 Testing YARA scanning on: %s\n", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Printf("❌ File not found: %s\n", filePath)
		return
	}

	// Create YARA scanner
	yaraScanner := scanner.NewYaraScanner(&cfg.Yara, logger)

	// Load rules
	if err := yaraScanner.LoadRules(); err != nil {
		logger.Warn("Failed to load YARA rules, creating test rules: %v", err)
		createTestRules(cfg.Yara.RulesPath)
		// Try loading again
		if err := yaraScanner.LoadRules(); err != nil {
			fmt.Printf("❌ Failed to load YARA rules after creating test rules: %v\n", err)
			return
		}
	}

	// Scan file
	result, err := yaraScanner.ScanFile(filePath)
	if err != nil {
		fmt.Printf("❌ Scan failed: %v\n", err)
		return
	}

	// Display results
	fmt.Printf("\n=== YARA Scan Results ===\n")
	fmt.Printf("File: %s\n", result.FilePath)
	fmt.Printf("Matched: %v\n", result.Matched)

	if result.Matched {
		fmt.Printf("🚨 THREAT DETECTED!\n")
		fmt.Printf("Rule: %s\n", result.RuleName)
		fmt.Printf("Severity: %d\n", result.Severity)
		fmt.Printf("Tags: %v\n", result.RuleTags)
		fmt.Printf("Description: %s\n", result.Description)
		fmt.Printf("File Hash: %s\n", result.FileHash)
	} else {
		fmt.Printf("✅ File is clean\n")
	}

	fmt.Printf("Scan Time: %dms\n", result.ScanTime)
	fmt.Printf("File Size: %d bytes\n", result.FileSize)

	fmt.Println("=========================")
}

// createTestRules creates test rules for demonstration
func createTestRules(rulesPath string) {
	// Create rules directory
	if err := os.MkdirAll(rulesPath, 0755); err != nil {
		fmt.Printf("Failed to create rules directory: %v\n", err)
		return
	}

	// Create test rule for demonstration
	testRule := `rule EICAR_Test {
    meta:
        description = "EICAR Standard Anti-Virus Test File"
        author = "EDR System"
        severity = 5
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

rule TestPowerShell {
    meta:
        description = "Test rule to detect PowerShell patterns"
        author = "EDR System"
        severity = 4
        threat_type = "powershell"
        tags = "powershell test"
    
    strings:
        $ps1 = "powershell"
        $ps2 = "PowerShell"
        $ps3 = "POWERSHELL"
    
    condition:
        any of them
}`

	// Write rule to file
	ruleFile := filepath.Join(rulesPath, "test_rules.yar")
	if err := os.WriteFile(ruleFile, []byte(testRule), 0644); err != nil {
		fmt.Printf("Failed to create test rule file: %v\n", err)
		return
	}

	// Create test malware file for demonstration
	testFile := "test_malware.txt"
	testContent := "This is a test malware file for EDR testing"

	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		fmt.Printf("Failed to create test file: %v\n", err)
	} else {
		fmt.Printf("📁 Created test file: %s\n", testFile)
		fmt.Printf("💡 You can test with: edr-agent.exe -test-yara %s\n", testFile)
	}

	// Create EICAR test file
	eicarContent := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	eicarFile := "eicar_test.txt"

	if err := os.WriteFile(eicarFile, []byte(eicarContent), 0644); err != nil {
		fmt.Printf("Failed to create EICAR test file: %v\n", err)
	} else {
		fmt.Printf("📁 Created EICAR test file: %s\n", eicarFile)
		fmt.Printf("💡 You can test with: edr-agent.exe -test-yara %s\n", eicarFile)
	}

	fmt.Printf("✅ Test files and rules created successfully\n")
	fmt.Printf("📂 Rules created in: %s\n", rulesPath)
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

// getYaraFilesFromGitHubAPI gets list of .yar files in a category from GitHub API
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
		fmt.Println("❌ No Internet connection. Cannot update YARA rules!")
		return fmt.Errorf("no internet connection")
	}

	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

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
				fmt.Printf("   ⏩ Already exists: %s, skipping\n", filepath.Join(category, file.Name))
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
	defer logger.Close()

	logger.Info("Generating system report...")

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
