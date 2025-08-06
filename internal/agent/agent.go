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

// Thực hiện đăng ký agent mới
func (a *Agent) performNewRegistration(macAddress string) error {
	// Lấy thông tin hệ thống
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

	systemInfo := a.getSystemInfo()

	// Tạo request đăng ký với authentication
	registration := communication.AgentRegistrationRequest{
		AuthToken:    a.config.Server.AuthToken, // Pre-shared auth token
		Hostname:     hostname,
		IPAddress:    ip,
		MACAddress:   macAddress,
		OSType:       runtime.GOOS,
		OSVersion:    osVersion,
		Architecture: runtime.GOARCH,
		AgentVersion: "1.0.0",
		SystemInfo:   systemInfo,
	}

	// Gửi request đăng ký
	result, err := a.serverClient.Register(registration)
	if err != nil {
		return fmt.Errorf("failed to register with server: %w", err)
	}

	// Cập nhật cấu hình với thông tin mới
	a.config.Agent.ID = result.AgentID
	if result.APIKey != "" {
		a.config.Server.APIKey = result.APIKey
		a.logger.Info("Updated API key from server")
	}

	// Lưu cấu hình
	if err := a.saveConfigToFile(); err != nil {
		a.logger.Warn("Failed to save agent config: %v", err)
	}

	a.logger.Info("Successfully registered new agent - ID: %s", result.AgentID)
	a.logger.Info("System Info - Hostname: %s, IP: %s, MAC: %s, OS: %s %s", hostname, ip, macAddress, runtime.GOOS, osVersion)
	return nil
}

// Lưu cấu hình agent vào file
func (a *Agent) saveConfigToFile() error {
	// Tìm đường dẫn config file
	configFile := "config.yaml"

	// Kiểm tra các vị trí có thể có của config file
	possiblePaths := []string{
		"config.yaml",
		"./config/config.yaml",
		"C:\\Program Files\\EDR-Agent\\config.yaml",
	}

	// Sử dụng file đầu tiên tồn tại hoặc tạo mới tại vị trí mặc định
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			configFile = path
			break
		}
	}

	// Sử dụng SaveWithBackup để tạo backup trước khi lưu
	return config.SaveWithBackup(a.config, configFile)
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
	// Bước 1: Lấy MAC address trước tiên
	macAddress, err := a.getMACAddress()
	if err != nil {
		a.logger.Warn("Failed to get MAC address: %v", err)
		return fmt.Errorf("cannot register without MAC address: %w", err)
	}

	a.logger.Info("Agent MAC Address: %s", macAddress)

	// Bước 2: Kiểm tra xem agent đã tồn tại chưa bằng MAC address
	exists, existingAgentID, existingAPIKey, err := a.serverClient.CheckAgentExistsByMAC(macAddress)
	if err != nil {
		a.logger.Error("Failed to check agent existence by MAC: %v", err)
		// Nếu không check được, vẫn tiếp tục đăng ký mới để tránh treo
	} else if exists {
		// Agent đã tồn tại, sử dụng thông tin hiện có
		a.logger.Info("Agent already exists with MAC %s, Agent ID: %s", macAddress, existingAgentID)

		// Cập nhật thông tin agent từ server
		a.config.Agent.ID = existingAgentID

		if existingAPIKey != "" {
			oldAPIKey := a.config.Server.APIKey
			a.config.Server.APIKey = existingAPIKey
			a.serverClient.UpdateAPIKey(existingAPIKey)
			a.logger.Info("Updated API key: %s -> %s", oldAPIKey, existingAPIKey)
		}

		// Lưu cấu hình đã cập nhật
		if err := a.saveConfigToFile(); err != nil {
			a.logger.Warn("Failed to save updated config: %v", err)
		}

		// Kiểm tra kết nối bằng heartbeat
		if err := a.sendHeartbeat(); err != nil {
			a.logger.Warn("Heartbeat failed with existing registration: %v", err)
			// Có thể server đã reset, thử đăng ký lại
			return a.performNewRegistration(macAddress)
		}

		a.logger.Info("Successfully connected with existing agent registration")
		return nil
	}

	// Bước 3: Agent chưa tồn tại, thực hiện đăng ký mới
	a.logger.Info("Agent not found with MAC %s, performing new registration", macAddress)
	return a.performNewRegistration(macAddress)
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

	// Ưu tiên 1: Interface có IP và đang hoạt động
	for _, iface := range interfaces {
		// Bỏ qua loopback và interface không hoạt động
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Kiểm tra có MAC address không
		if iface.HardwareAddr == nil {
			continue
		}

		// Kiểm tra interface có IPv4 address không
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		hasIPv4 := false
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
					hasIPv4 = true
					break
				}
			}
		}

		if hasIPv4 {
			macAddr := iface.HardwareAddr.String()
			a.logger.Debug("Selected primary interface: %s, MAC: %s", iface.Name, macAddr)
			return macAddr, nil
		}
	}

	// Ưu tiên 2: Bất kỳ interface nào có MAC address và đang hoạt động
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.HardwareAddr != nil {
			macAddr := iface.HardwareAddr.String()
			a.logger.Debug("Selected fallback interface: %s, MAC: %s", iface.Name, macAddr)
			return macAddr, nil
		}
	}

	return "", fmt.Errorf("no suitable MAC address found")
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
