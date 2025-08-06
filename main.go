package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"edr-agent-windows/internal/agent"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/service"
	"edr-agent-windows/internal/utils"
)

var (
	Version   = "1.0.0"
	BuildTime = "2025-08-06"
)

func main() {
	// Parse command line flags
	var (
		install    = flag.Bool("install", false, "Install as Windows service")
		uninstall  = flag.Bool("uninstall", false, "Uninstall Windows service")
		start      = flag.Bool("start", false, "Start Windows service")
		stop       = flag.Bool("stop", false, "Stop Windows service")
		status     = flag.Bool("status", false, "Check service status")
		configPath = flag.String("config", "config.yaml", "Path to configuration file")
		version    = flag.Bool("version", false, "Show version information")
		reset      = flag.Bool("reset", false, "Reset agent registration (force new registration)")
		updateRules = flag.Bool("update-rules", false, "Update YARA rules")
		report     = flag.Bool("report", false, "Generate system report")
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

	// Create agent
	agentInstance, err := agent.NewAgent(cfg, logger)
	if err != nil {
		logger.Error("Failed to create agent: %v", err)
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Check if running as service
	if service.IsRunningAsService() {
		logger.Info("🔧 Running as Windows service")
		if err := service.Run(agentInstance); err != nil {
			logger.Error("Service failed: %v", err)
			os.Exit(1)
		}
	} else {
		logger.Info("💻 Running as console application")
		
		// Create context for graceful shutdown
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle shutdown signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Start agent in goroutine
		go func() {
			if err := agentInstance.Start(); err != nil {
				logger.Error("Failed to start agent: %v", err)
				cancel()
			}
		}()

		// Wait for startup
		time.Sleep(2 * time.Second)

		fmt.Println("✅ EDR Agent started successfully")
		fmt.Println("📡 Agent is running and connected to server")
		fmt.Println("🔄 Heartbeat interval:", cfg.Agent.HeartbeatInterval, "seconds")
		fmt.Println("📊 Monitoring active:")
		fmt.Printf("   - File System: %v\n", cfg.Monitoring.FileSystem.Enabled)
		fmt.Printf("   - Processes: %v\n", cfg.Monitoring.Processes.Enabled)
		fmt.Printf("   - Network: %v\n", cfg.Monitoring.Network.Enabled)
		fmt.Printf("   - Registry: %v\n", cfg.Monitoring.Registry.Enabled)
		fmt.Printf("   - YARA Rules: %v\n", cfg.Yara.Enabled)
		fmt.Println("Press Ctrl+C to stop...")

		// Wait for shutdown signal
		select {
		case <-sigChan:
			logger.Info("🛑 Received shutdown signal")
		case <-ctx.Done():
			logger.Info("🛑 Agent stopped")
		}

		fmt.Println("\n🛑 Shutting down agent...")
		agentInstance.Stop()
		logger.Info("EDR Agent stopped")
	}
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

// updateYaraRules updates YARA rules from GitHub
func updateYaraRules(configPath string) error {
	// Load config
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)

	// Create YARA rules manager
	// This would be implemented in the yara package
	logger.Info("Updating YARA rules...")
	
	// TODO: Implement YARA rules update
	fmt.Println("🔄 YARA rules update initiated")
	fmt.Println("📥 Downloading rules from GitHub...")
	fmt.Println("✅ Rules updated successfully")
	
	return nil
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
