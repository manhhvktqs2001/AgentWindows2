package agent

import (
	"fmt"
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
	registration := communication.AgentRegistration{
		Hostname:     a.config.Agent.Name,
		IPAddress:    "192.168.20.85", // TODO: Get actual IP
		OSType:       "Windows",
		OSVersion:    "10.0.19044", // TODO: Get actual version
		Architecture: "x64",
		AgentVersion: "1.0.0",
	}

	agentID, err := a.serverClient.Register(registration)
	if err != nil {
		return err
	}

	a.config.Agent.ID = agentID
	a.logger.Info("Registered with server, Agent ID: %s", agentID)

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
	ticker := time.NewTicker(5 * time.Second) // Send batch every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-a.stopChan:
			// Send remaining events
			if len(events) > 0 {
				a.serverClient.SendEvents(events)
			}
			return

		case event := <-a.eventChan:
			events = append(events, event)

			// Send batch when full
			if len(events) >= a.config.Agent.EventBatchSize {
				a.serverClient.SendEvents(events)
				events = events[:0] // Reset slice
			}

		case <-ticker.C:
			// Send batch on timer
			if len(events) > 0 {
				a.serverClient.SendEvents(events)
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
