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
		configPath = flag.String("config", "", "Path to configuration file")
		version    = flag.Bool("version", false, "Show version information")
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
		fmt.Println("EDR Agent service installed successfully")
		return
	}

	if *uninstall {
		if err := service.Uninstall(); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("EDR Agent service uninstalled successfully")
		return
	}

	if *start {
		if err := service.Start(); err != nil {
			log.Fatalf("Failed to start service: %v", err)
		}
		fmt.Println("EDR Agent service started successfully")
		return
	}

	if *stop {
		if err := service.Stop(); err != nil {
			log.Fatalf("Failed to stop service: %v", err)
		}
		fmt.Println("EDR Agent service stopped successfully")
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

	// Load configuration
	var cfg *config.Config
	var err error

	if *configPath != "" {
		// Use provided config file
		cfg, err = config.Load(*configPath)
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	} else {
		// Use built-in default config
		cfg = getDefaultConfig()
		fmt.Println("✅ Using built-in default configuration")
	}

	// Initialize logger
	logger := utils.NewLogger(&cfg.Log)

	// Create and start agent
	agent, err := agent.NewAgent(cfg, logger)
	if err != nil {
		log.Fatalf("Failed to create agent: %v", err)
	}

	// Check if running as service
	if service.IsRunningAsService() {
		logger.Info("Running as Windows service")
		if err := service.Run(agent); err != nil {
			logger.Error("Service failed: %v", err)
			os.Exit(1)
		}
	} else {
		logger.Info("Running as console application")
		if err := agent.Start(); err != nil {
			logger.Error("Failed to start agent: %v", err)
			os.Exit(1)
		}

		// Wait for interrupt signal
		utils.WaitForInterrupt()
		agent.Stop()
	}
}

// getDefaultConfig returns built-in default configuration
func getDefaultConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			URL:        "http://192.168.20.85:5000",
			APIKey:     "f93ac1d1d7b64f07bd32c81e6ab8423e4cb7631f2051c9d8a2d340c5be3a4a9e",
			Timeout:    30,
			RetryCount: 3,
			TLSVerify:  false,
		},
		Agent: config.AgentDetails{
			ID:                "",
			Name:              "edr-agent-windows",
			HeartbeatInterval: 60,
			EventBatchSize:    100,
			MaxQueueSize:      10000,
		},
		Monitor: config.MonitorConfig{
			Files: config.FileMonitorConfig{
				Enabled:     false,
				Paths:       []string{},
				Recursive:   false,
				ScanOnWrite: false,
				MaxFileSize: "100MB",
				ExcludeExts: []string{},
			},
			Processes: config.ProcessMonitorConfig{
				Enabled:        false,
				ScanExecutable: false,
				MonitorCmdLine: false,
				ExcludeNames:   []string{},
			},
			Network: config.NetworkMonitorConfig{
				Enabled:      false,
				MonitorTCP:   false,
				MonitorUDP:   false,
				ExcludePorts: []int{},
			},
			Registry: config.RegistryMonitorConfig{
				Enabled: false,
				Keys:    []string{},
			},
		},
		Scanner: config.ScannerConfig{
			YaraEnabled:    false,
			YaraRulesPath:  "",
			MaxScanThreads: 1,
			ScanTimeout:    30,
		},
		Log: config.LogConfig{
			Level:    "info",
			Format:   "text",
			FilePath: "agent.log",
			MaxSize:  10,
		},
	}
}
