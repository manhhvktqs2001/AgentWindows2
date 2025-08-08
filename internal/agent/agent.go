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
	"edr-agent-windows/internal/response"
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
	yaraScanner := scanner.NewYaraScanner(&cfg.Yara, logger)

	// Initialize monitors
	fileMonitor := monitoring.NewFileMonitor(&cfg.Monitoring.FileSystem, logger, yaraScanner)
	processMonitor := monitoring.NewProcessMonitor(&cfg.Monitoring.Processes, logger)
	networkMonitor := monitoring.NewNetworkMonitor(&cfg.Monitoring.Network, logger)
	registryMonitor := monitoring.NewRegistryMonitor(&cfg.Monitoring.Registry, logger)

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

	// Wire server client and response manager to scanner for alerting/notifications
	yaraScanner.SetServerClient(serverClient)

	// Create and start Response Manager
	responseManager := response.NewResponseManager(&cfg.Response, logger, serverClient)
	if err := responseManager.Start(); err != nil {
		logger.Error("Failed to start Response Manager: %v", err)
	} else {
		// Pass Response Manager to scanner so detections trigger user notifications and actions
		yaraScanner.SetResponseManager(responseManager)
	}

	// Propagate AgentID to scanner if already set in config
	if cfg.Agent.ID != "" {
		yaraScanner.SetAgentID(cfg.Agent.ID)
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

	// Propagate AgentID to serverClient and monitors
	a.serverClient.SetAgentID(a.config.Agent.ID)
	// Also propagate to scanner so alerts include agent_id
	if a.scanner != nil {
		a.scanner.SetAgentID(a.config.Agent.ID)
		if loadErr := a.scanner.LoadRules(); loadErr != nil {
			a.logger.Warn("Failed to load YARA rules: %v", loadErr)
		}
	}
	a.fileMonitor.SetAgentID(a.config.Agent.ID)
	a.processMonitor.SetAgentID(a.config.Agent.ID)
	a.networkMonitor.SetAgentID(a.config.Agent.ID)
	a.registryMonitor.SetAgentID(a.config.Agent.ID)

	// Start monitors
	if a.config.Monitoring.FileSystem.Enabled {
		err = a.fileMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start file monitor: %v", err)
		}
	}

	if a.config.Monitoring.Processes.Enabled {
		err = a.processMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start process monitor: %v", err)
		}
	}

	if a.config.Monitoring.Network.Enabled {
		err = a.networkMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start network monitor: %v", err)
		}
	}

	if a.config.Monitoring.Registry.Enabled {
		err = a.registryMonitor.Start()
		if err != nil {
			a.logger.Error("Failed to start registry monitor: %v", err)
		}
	}

	// Start background workers
	go a.heartbeatWorker()
	go a.eventWorker()
	go a.taskWorker()
	go a.monitorEventWorker() // Start the new monitor event worker

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
	a.logger.Debug("Registering event: %s from agent %s", event.GetType(), event.GetAgentID())
	select {
	case a.eventChan <- event:
		a.logger.Debug("Event registered successfully: %s", event.GetType())
	default:
		a.logger.Warn("Event queue full, dropping event: %s", event.GetType())
	}
}

// Register with server
func (a *Agent) registerWithServer() error {
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

	// Try check-by-MAC first
	exists, agentID, apiKey, err := a.serverClient.CheckAgentExistsByMAC(a.getPrimaryMAC())
	if err == nil && exists {
		a.config.Agent.ID = agentID
		if apiKey != "" {
			a.config.Server.APIKey = apiKey
		}
		a.logger.Info("Agent exists on server, using ID: %s", agentID)
		return nil
	}

	registration := communication.AgentRegistrationRequest{
		AuthToken:    a.config.Server.AuthToken,
		Hostname:     hostname,
		IPAddress:    ip,
		MACAddress:   a.getPrimaryMAC(),
		OSType:       runtime.GOOS,
		OSVersion:    osVersion,
		Architecture: runtime.GOARCH,
		AgentVersion: "1.0.0",
		SystemInfo:   map[string]interface{}{},
	}

	resp, err := a.serverClient.Register(registration)
	if err != nil {
		return err
	}

	a.config.Agent.ID = resp.AgentID
	if resp.APIKey != "" {
		a.config.Server.APIKey = resp.APIKey
	}

	a.logger.Info("Registered with server, Agent ID: %s", resp.AgentID)
	return nil
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
	ticker := time.NewTicker(2 * time.Second) // Send batch every 2 seconds instead of 5
	defer ticker.Stop()

	a.logger.Info("Event worker started - will send events to server every 2 seconds or when batch is full")

	for {
		select {
		case <-a.stopChan:
			// Send remaining events
			if len(events) > 0 {
				a.logger.Info("Sending %d remaining events to server", len(events))
				// Convert []Event to []interface{}
				interfaceEvents := make([]interface{}, len(events))
				for i, event := range events {
					interfaceEvents[i] = event
				}
				a.serverClient.SendEvents(interfaceEvents)
			}
			return

		case event := <-a.eventChan:
			a.logger.Debug("Received event in eventWorker: %s", event.GetType())
			events = append(events, event)

			// Send batch when full or when we have a significant number
			if len(events) >= a.config.Agent.EventBatchSize || len(events) >= 50 {
				a.logger.Info("Sending batch of %d events to server (batch full)", len(events))
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
				a.logger.Info("Sending batch of %d events to server (timer)", len(events))
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

// monitorEventWorker collects events from all monitors and sends them to the agent's event system
func (a *Agent) monitorEventWorker() {
	// Get event channels from all monitors
	fileEvents := a.fileMonitor.GetEventChannel()
	processEvents := a.processMonitor.GetEventChannel()
	networkEvents := a.networkMonitor.GetEventChannel()
	registryEvents := a.registryMonitor.GetEventChannel()

	a.logger.Info("Monitor event worker started - listening for events from all monitors")

	for {
		select {
		case <-a.stopChan:
			a.logger.Info("Monitor event worker stopped")
			return
		case event := <-fileEvents:
			// Convert FileEvent to Event interface and register
			a.logger.Debug("Received file event: %s", event.EventType)
			a.RegisterEvent(&event)
		case event := <-processEvents:
			// Convert ProcessEvent to Event interface and register
			a.logger.Debug("Received process event: %s", event.EventType)
			a.RegisterEvent(&event)
		case event := <-networkEvents:
			// Convert NetworkEvent to Event interface and register
			a.logger.Debug("Received network event: %s", event.EventType)
			a.RegisterEvent(&event)
		case event := <-registryEvents:
			// Convert RegistryEvent to Event interface and register
			a.logger.Debug("Received registry event: %s", event.EventType)
			a.RegisterEvent(&event)
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

// getPrimaryMAC returns the first non-loopback MAC address
func (a *Agent) getPrimaryMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
			continue
		}
		return iface.HardwareAddr.String()
	}
	return ""
}
