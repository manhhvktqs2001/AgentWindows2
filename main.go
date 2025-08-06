package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

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
	logger.Info("=== EDR Agent Starting ===")
	logger.Info("Version: %s", Version)
	logger.Info("Build Time: %s", BuildTime)
	logger.Info("Config Path: %s", *configPath)
	logger.Info("Agent Name: %s", cfg.Agent.Name)
	logger.Info("Server URL: %s", cfg.Server.URL)

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
		
		// Start agent
		if err := agentInstance.Start(); err != nil {
			logger.Error("Failed to start agent: %v", err)
			os.Exit(1)
		}

		fmt.Println("✅ EDR Agent started successfully")
		fmt.Println("📡 Agent is running and connected to server")
		fmt.Println("🔄 Heartbeat interval:", cfg.Agent.HeartbeatInterval, "seconds")
		fmt.Println("Press Ctrl+C to stop...")

		// Wait for interrupt signal
		utils.WaitForInterrupt()
		
		fmt.Println("\n🛑 Shutting down agent...")
		agentInstance.Stop()
		logger.Info("EDR Agent stopped")
	}
}

// resetAgentRegistration xóa thông tin đăng ký agent để force đăng ký lại
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
