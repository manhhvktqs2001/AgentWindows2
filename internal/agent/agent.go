package agent

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"edr-agent-windows/internal/communication"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/monitoring"
	"edr-agent-windows/internal/scanner"
	"edr-agent-windows/internal/utils"
)

type Agent struct {
	config       *config.Config
	logger       *utils.Logger
	serverClient *communication.ServerClient
	scanner      *scanner.YaraScanner

	// Monitors
	fileMonitor     *monitoring.FileMonitor
	processMonitor  *monitoring.ProcessMonitor
	networkMonitor  *monitoring.NetworkMonitor
	registryMonitor *monitoring.RegistryMonitor

	// Control channels
	stopChan  chan bool
	eventChan chan Event
	taskChan  chan Task

	// State
	isRunning bool
	mu        sync.RWMutex
}

type Event interface {
	GetType() string
	GetTimestamp() time.Time
	GetAgentID() string
	ToJSON() []byte
}

type Task interface {
	GetID() string
	GetType() string
	Execute() error
}

// Create new agent
func NewAgent(cfg *config.Config, logger *utils.Logger) (*Agent, error) {
	// Initialize server client
	serverClient := communication.NewServerClient(cfg.Server, logger)

	// Initialize YARA scanner
	yaraScanner := scanner.NewYaraScanner(cfg.Scanner, logger)

	// Initialize monitors
	fileMonitor := monitoring.NewFileMonitor(cfg.Monitor.Files, logger, yaraScanner)
	processMonitor := monitoring.NewProcessMonitor(cfg.Monitor.Processes, logger, yaraScanner)
	networkMonitor := monitoring.NewNetworkMonitor(cfg.Monitor.Network, logger)
	registryMonitor := monitoring.NewRegistryMonitor(cfg.Monitor.Registry, logger)

	agent := &Agent{
		config:          cfg,
		logger:          logger,
		serverClient:    serverClient,
		scanner:         yaraScanner,
		fileMonitor:     fileMonitor,
		processMonitor:  processMonitor,
		networkMonitor:  networkMonitor,
		registryMonitor: registryMonitor,
		stopChan:        make(chan bool),
		eventChan:       make(chan Event, cfg.Agent.MaxQueueSize),
		taskChan:        make(chan Task, 100),
	}

	return agent, nil
}

// Start agent
func (a *Agent) Start() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.isRunning {
		return fmt.Errorf("agent already running")
	}

	a.logger.Info("Starting EDR Agent...")

	// Register with server
	err := a.registerWithServer()
	if err != nil {
		return fmt.Errorf("failed to register with server: %w", err)
	}

	// Start monitors
	if a.config.Monitor.Files.Enabled {
		err = a.fileMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start file monitor: %v", err)
		}
	}

	if a.config.Monitor.Processes.Enabled {
		err = a.processMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start process monitor: %v", err)
		}
	}

	if a.config.Monitor.Network.Enabled {
		err = a.networkMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start network monitor: %v", err)
		}
	}

	if a.config.Monitor.Registry.Enabled {
		err = a.registryMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start registry monitor: %v", err)
		}
	}

	// Start background workers
	go a.heartbeatWorker()
	go a.eventWorker()
	go a.taskWorker()

	a.isRunning = true
	a.logger.Info("EDR Agent started successfully")

	return nil
}

// Stop agent
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.isRunning {
		return
	}

	a.logger.Info("Stopping EDR Agent...")

	// Signal stop to all workers
	close(a.stopChan)

	// Stop monitors
	a.fileMonitor.Stop()
	a.processMonitor.Stop()
	a.networkMonitor.Stop()
	a.registryMonitor.Stop()

	a.isRunning = false
	a.logger.Info("EDR Agent stopped")
}

// Register event
func (a *Agent) RegisterEvent(event Event) {
	select {
	case a.eventChan <- event:
	default:
		a.logger.Warn("Event queue full, dropping event")
	}
}

// Register with server
func (a *Agent) registerWithServer() error {
	// Get MAC address first
	macAddress, err := a.getMACAddress()
	if err != nil {
		a.logger.Warn("Failed to get MAC address: %v", err)
		macAddress = ""
	}

	// Check if agent already exists by MAC address
	if macAddress != "" {
		a.logger.Info("Checking if agent exists by MAC: %s", macAddress)

		exists, existingAgentID, existingAPIKey, err := a.serverClient.CheckAgentExistsByMAC(macAddress)
		if err != nil {
			a.logger.Warn("Failed to check agent existence by MAC: %v", err)
		} else if exists {
			a.logger.Info("Agent already exists with MAC %s, Agent ID: %s", macAddress, existingAgentID)
			a.logger.Info("Received API key from server: %s", existingAPIKey)

			// Update local config with existing agent ID and API key
			a.config.Agent.ID = existingAgentID
			if existingAPIKey != "" {
				oldAPIKey := a.config.Server.APIKey
				a.config.Server.APIKey = existingAPIKey
				a.logger.Info("Updated API key from existing agent: %s -> %s", oldAPIKey, existingAPIKey)

				// Update server client with new API key
				a.serverClient.UpdateAPIKey(existingAPIKey)
				a.logger.Info("Updated server client with new API key")

				// Save updated config to file
				err := config.Save(a.config, "config.yaml")
				if err != nil {
					a.logger.Warn("Failed to save updated config: %v", err)
				} else {
					a.logger.Info("Saved updated config with new API key")
				}
			} else {
				a.logger.Warn("No API key received from server")
			}

			// Try to send a heartbeat to verify the registration is still valid
			err := a.sendHeartbeat()
			if err == nil {
				a.logger.Info("Existing registration is valid, skipping registration")
				return nil
			} else {
				a.logger.Warn("Heartbeat failed, but agent exists on server: %v", err)
				a.logger.Info("Continuing with existing registration")
				return nil
			}
		} else {
			a.logger.Info("No existing agent found with MAC %s, proceeding with registration", macAddress)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	ip, err := a.getIPAddress()
	if err != nil {
		return fmt.Errorf("failed to get IP address: %w", err)
	}

	osVersion, err := a.getOSVersion()
	if err != nil {
		return fmt.Errorf("failed to get OS version: %w", err)
	}

	// Get additional system information
	systemInfo := a.getSystemInfo()

	registration := communication.AgentRegistration{
		Hostname:     hostname,
		IPAddress:    ip,
		MACAddress:   macAddress,
		OSType:       runtime.GOOS,
		OSVersion:    osVersion,
		Architecture: runtime.GOARCH,
		AgentVersion: "1.0.0",
		SystemInfo:   systemInfo,
	}

	agentID, err := a.serverClient.Register(registration)
	if err != nil {
		return err
	}

	a.config.Agent.ID = agentID

	// Update API key if server provided a new one
	if a.serverClient.GetAPIKey() != a.config.Server.APIKey {
		a.config.Server.APIKey = a.serverClient.GetAPIKey()
		a.logger.Info("Updated API key from server")
	}

	a.logger.Info("Registered with server, Agent ID: %s", agentID)
	a.logger.Info("System Info - Hostname: %s, IP: %s, MAC: %s, OS: %s %s", hostname, ip, macAddress, runtime.GOOS, osVersion)

	// Save agent ID to config file
	err = a.saveAgentID(agentID)
	if err != nil {
		a.logger.Warn("Failed to save agent ID to config: %v", err)
	}

	return nil
}

// saveAgentID saves the agent ID and API key to the config file
func (a *Agent) saveAgentID(agentID string) error {
	// Update the config with the new agent ID and API key
	a.config.Agent.ID = agentID
	a.config.Server.APIKey = a.serverClient.GetAPIKey()

	// Save to config file
	return config.Save(a.config, "config.yaml")
}

// Send heartbeat
func (a *Agent) sendHeartbeat() error {
	data := communication.HeartbeatData{
		AgentID:   a.config.Agent.ID,
		Timestamp: time.Now(),
		Status:    "online",
		SystemInfo: map[string]interface{}{
			"cpu_usage":    0.0, // TODO: Get actual CPU usage
			"memory_usage": 0.0, // TODO: Get actual memory usage
			"disk_usage":   0.0, // TODO: Get actual disk usage
		},
		Metrics: map[string]interface{}{
			"events_sent":      0, // TODO: Track metrics
			"files_scanned":    0,
			"alerts_generated": 0,
		},
	}

	return a.serverClient.SendHeartbeat(data)
}

// Background workers
func (a *Agent) heartbeatWorker() {
	ticker := time.NewTicker(time.Duration(a.config.Agent.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.stopChan:
			return
		case <-ticker.C:
			err := a.sendHeartbeat()
			if err != nil {
				a.logger.Error("Failed to send heartbeat: %v", err)
			}
		}
	}
}

func (a *Agent) eventWorker() {
	events := make([]Event, 0, a.config.Agent.EventBatchSize)
	ticker := time.NewTicker(5 * time.Second) // Send batch every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-a.stopChan:
			// Send remaining events
			if len(events) > 0 {
				// Convert []Event to []interface{}
				interfaceEvents := make([]interface{}, len(events))
				for i, event := range events {
					interfaceEvents[i] = event
				}
				a.serverClient.SendEvents(interfaceEvents)
			}
			return

		case event := <-a.eventChan:
			events = append(events, event)

			// Send batch when full
			if len(events) >= a.config.Agent.EventBatchSize {
				// Convert []Event to []interface{}
				interfaceEvents := make([]interface{}, len(events))
				for i, event := range events {
					interfaceEvents[i] = event
				}
				a.serverClient.SendEvents(interfaceEvents)
				events = events[:0] // Reset slice
			}

		case <-ticker.C:
			// Send batch on timer
			if len(events) > 0 {
				// Convert []Event to []interface{}
				interfaceEvents := make([]interface{}, len(events))
				for i, event := range events {
					interfaceEvents[i] = event
				}
				a.serverClient.SendEvents(interfaceEvents)
				events = events[:0] // Reset slice
			}
		}
	}
}

func (a *Agent) taskWorker() {
	for {
		select {
		case <-a.stopChan:
			return
		case task := <-a.taskChan:
			err := task.Execute()
			if err != nil {
				a.logger.Error("Task execution failed: %v", err)
			}
		}
	}
}

func (a *Agent) getIPAddress() (string, error) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// Look for the primary network interface (usually the first non-loopback interface)
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				// Get IPv4 address
				if ip := ipnet.IP.To4(); ip != nil {
					return ip.String(), nil
				}
			}
		}
	}

	// Fallback: try to get any non-loopback IPv4 address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ip := ipnet.IP.To4(); ip != nil {
				return ip.String(), nil
			}
		}
	}

	return "127.0.0.1", nil // Fallback to localhost
}

func (a *Agent) getMACAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	// Look for the primary network interface (usually the first non-loopback interface with IPv4)
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Check if interface has IPv4 address
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		hasIPv4 := false
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil {
					hasIPv4 = true
					break
				}
			}
		}

		// If interface has IPv4 and MAC address, use it
		if hasIPv4 && iface.HardwareAddr != nil {
			return iface.HardwareAddr.String(), nil
		}
	}

	// Fallback: get any MAC address
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.HardwareAddr != nil {
			return iface.HardwareAddr.String(), nil
		}
	}

	return "", fmt.Errorf("no MAC address found")
}

func (a *Agent) getSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"cpu_cores":  runtime.NumCPU(),
		"go_version": runtime.Version(),
		"go_os":      runtime.GOOS,
		"go_arch":    runtime.GOARCH,
		"hostname":   a.getHostname(),
	}
}

func (a *Agent) getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func (a *Agent) getOSVersion() (string, error) {
	// Try to get Windows version from registry or system info
	// For now, return a basic version based on runtime
	switch runtime.GOOS {
	case "windows":
		return "Windows 10", nil
	default:
		return runtime.GOOS, nil
	}
}
