package monitoring

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"

	"golang.org/x/sys/windows"
)

type NetworkMonitor struct {
	config      *config.NetworkConfig
	logger      *utils.Logger
	eventChan   chan models.NetworkEvent
	stopChan    chan bool
	agentID     string
	connections map[string]*NetworkConnectionInfo
}

type NetworkConnectionInfo struct {
	LocalIP     string
	LocalPort   uint16
	RemoteIP    string
	RemotePort  uint16
	Protocol    string
	State       string
	ProcessID   uint32
	ProcessName string
	LastSeen    time.Time
}

const (
	AF_INET  = 2
	AF_INET6 = 23

	TCP_ESTABLISHED = 1
	TCP_SYN_SENT    = 2
	TCP_SYN_RECV    = 3
	TCP_FIN_WAIT1   = 4
	TCP_FIN_WAIT2   = 5
	TCP_TIME_WAIT   = 6
	TCP_CLOSE       = 7
	TCP_CLOSE_WAIT  = 8
	TCP_LAST_ACK    = 9
	TCP_LISTEN      = 10
	TCP_CLOSING     = 11

	UDP_STATE = 0
)

var (
	netIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")
	netKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	netPsapi    = windows.NewLazySystemDLL("psapi.dll")

	procGetExtendedTcpTable     = netIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable     = netIphlpapi.NewProc("GetExtendedUdpTable")
	netProcOpenProcess          = netKernel32.NewProc("OpenProcess")
	netProcGetModuleFileNameExW = netPsapi.NewProc("GetModuleFileNameExW")
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	ProcessId  uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	ProcessId uint32
}

func NewNetworkMonitor(cfg *config.NetworkConfig, logger *utils.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		config:      cfg,
		logger:      logger,
		eventChan:   make(chan models.NetworkEvent, 1000),
		stopChan:    make(chan bool),
		agentID:     "",
		connections: make(map[string]*NetworkConnectionInfo),
	}
}

func (nm *NetworkMonitor) Start() error {
	nm.logger.Info("Starting network monitor...")

	// Get initial network connections
	if err := nm.enumerateConnections(); err != nil {
		nm.logger.Warn("Failed to enumerate initial connections: %v", err)
	}

	// Start monitoring goroutine
	go nm.monitorConnections()

	nm.logger.Info("Network monitor started successfully")
	return nil
}

func (nm *NetworkMonitor) Stop() {
	nm.logger.Info("Stopping network monitor...")
	close(nm.stopChan)
	close(nm.eventChan)
	nm.logger.Info("Network monitor stopped")
}

func (nm *NetworkMonitor) GetEventChannel() <-chan models.NetworkEvent {
	return nm.eventChan
}

func (nm *NetworkMonitor) SetAgentID(agentID string) {
	nm.agentID = agentID
}

func (nm *NetworkMonitor) enumerateConnections() error {
	// Enumerate TCP connections
	if err := nm.enumerateTCPConnections(); err != nil {
		return fmt.Errorf("failed to enumerate TCP connections: %w", err)
	}

	// Enumerate UDP connections
	if err := nm.enumerateUDPConnections(); err != nil {
		return fmt.Errorf("failed to enumerate UDP connections: %w", err)
	}

	return nil
}

func (nm *NetworkMonitor) enumerateTCPConnections() error {
	var size uint32
	var table []MIB_TCPROW_OWNER_PID

	// Get required size
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		1, // TCP_TABLE_OWNER_PID_ALL
		0,
	)

	if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
		return fmt.Errorf("failed to get TCP table size: %d", ret)
	}

	// Allocate buffer
	table = make([]MIB_TCPROW_OWNER_PID, size/uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{})))

	// Get TCP table
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&table[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		1, // TCP_TABLE_OWNER_PID_ALL
		0,
	)

	if ret != 0 {
		return fmt.Errorf("failed to get TCP table: %d", ret)
	}

	// Process connections
	for _, row := range table {
		conn := &NetworkConnectionInfo{
			LocalIP:    nm.ipToString(row.LocalAddr),
			LocalPort:  nm.portToHostByteOrder(row.LocalPort),
			RemoteIP:   nm.ipToString(row.RemoteAddr),
			RemotePort: nm.portToHostByteOrder(row.RemotePort),
			Protocol:   "TCP",
			State:      nm.tcpStateToString(row.State),
			ProcessID:  row.ProcessId,
			LastSeen:   time.Now(),
		}

		// Get process name
		if processName, err := nm.getProcessName(row.ProcessId); err == nil {
			conn.ProcessName = processName
		}

		// Generate connection key
		key := nm.generateConnectionKey(conn)
		nm.connections[key] = conn

		// Create event
		nm.createNetworkEvent(conn, "connection_established")
	}

	return nil
}

func (nm *NetworkMonitor) enumerateUDPConnections() error {
	var size uint32
	var table []MIB_UDPROW_OWNER_PID

	// Get required size
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		1, // UDP_TABLE_OWNER_PID
		0,
	)

	if ret != 122 { // ERROR_INSUFFICIENT_BUFFER
		return fmt.Errorf("failed to get UDP table size: %d", ret)
	}

	// Allocate buffer
	table = make([]MIB_UDPROW_OWNER_PID, size/uint32(unsafe.Sizeof(MIB_UDPROW_OWNER_PID{})))

	// Get UDP table
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&table[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		1, // UDP_TABLE_OWNER_PID
		0,
	)

	if ret != 0 {
		return fmt.Errorf("failed to get UDP table: %d", ret)
	}

	// Process connections
	for _, row := range table {
		conn := &NetworkConnectionInfo{
			LocalIP:    nm.ipToString(row.LocalAddr),
			LocalPort:  nm.portToHostByteOrder(row.LocalPort),
			RemoteIP:   "",
			RemotePort: 0,
			Protocol:   "UDP",
			State:      "LISTENING",
			ProcessID:  row.ProcessId,
			LastSeen:   time.Now(),
		}

		// Get process name
		if processName, err := nm.getProcessName(row.ProcessId); err == nil {
			conn.ProcessName = processName
		}

		// Generate connection key
		key := nm.generateConnectionKey(conn)
		nm.connections[key] = conn

		// Create event
		nm.createNetworkEvent(conn, "connection_established")
	}

	return nil
}

func (nm *NetworkMonitor) monitorConnections() {
	ticker := time.NewTicker(time.Duration(nm.config.ScanInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nm.stopChan:
			return
		case <-ticker.C:
			nm.checkConnections()
		}
	}
}

func (nm *NetworkMonitor) checkConnections() {
	currentConnections := make(map[string]*NetworkConnectionInfo)

	// Get current connections
	if err := nm.enumerateConnections(); err != nil {
		nm.logger.Error("Failed to enumerate connections: %v", err)
		return
	}

	// Check for new connections
	for key, conn := range nm.connections {
		if _, exists := currentConnections[key]; !exists {
			// Connection closed
			nm.createNetworkEvent(conn, "connection_closed")
			delete(nm.connections, key)
		}
	}

	// Check for new connections
	for key, conn := range currentConnections {
		if _, exists := nm.connections[key]; !exists {
			// New connection
			nm.connections[key] = conn
			nm.createNetworkEvent(conn, "connection_established")
		}
	}
}

func (nm *NetworkMonitor) createNetworkEvent(conn *NetworkConnectionInfo, action string) {
	// Determine severity
	severity := nm.determineNetworkSeverity(conn)

	// Create event
	event := models.NetworkEvent{
		Event: models.Event{
			ID:        nm.generateEventID(),
			AgentID:   nm.agentID,
			Timestamp: time.Now(),
			EventType: "network_event",
			Severity:  severity,
			Source:    "network_monitor",
		},
		ConnectionID:  nm.generateConnectionKey(conn),
		BytesSent:     0,
		BytesReceived: 0,
		Duration:      0,
		Status:        conn.State,
	}

	// Send event
	select {
	case nm.eventChan <- event:
		nm.logger.Debug("Network event sent: %s %s:%d -> %s:%d", action, conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)
	default:
		nm.logger.Warn("Network event channel full, dropping event")
	}
}

func (nm *NetworkMonitor) determineNetworkSeverity(conn *NetworkConnectionInfo) string {
	// Check for suspicious patterns
	if nm.isSuspiciousConnection(conn) {
		return "high"
	}

	// Check for known malicious IPs
	if nm.isKnownMaliciousIP(conn.RemoteIP) {
		return "critical"
	}

	// Check for unusual ports
	if nm.isUnusualPort(conn.RemotePort) {
		return "medium"
	}

	return "low"
}

func (nm *NetworkMonitor) isSuspiciousConnection(conn *NetworkConnectionInfo) bool {
	// Check for connections to suspicious ports
	suspiciousPorts := []uint16{22, 23, 3389, 5900, 8080, 4444, 1337}
	for _, port := range suspiciousPorts {
		if conn.RemotePort == port {
			return true
		}
	}

	// Check for connections to private IP ranges from external
	if nm.isPrivateIP(conn.RemoteIP) && !nm.isPrivateIP(conn.LocalIP) {
		return true
	}

	return false
}

func (nm *NetworkMonitor) isKnownMaliciousIP(ip string) bool {
	// TODO: Implement threat intelligence lookup
	maliciousIPs := []string{
		"192.168.1.100", // Example malicious IP
		"10.0.0.50",     // Example malicious IP
	}

	for _, maliciousIP := range maliciousIPs {
		if ip == maliciousIP {
			return true
		}
	}

	return false
}

func (nm *NetworkMonitor) isUnusualPort(port uint16) bool {
	// Common ports that are usually safe
	commonPorts := []uint16{80, 443, 21, 25, 110, 143, 993, 995, 587, 465}
	for _, commonPort := range commonPorts {
		if port == commonPort {
			return false
		}
	}
	return true
}

func (nm *NetworkMonitor) isPrivateIP(ip string) bool {
	// Check if IP is in private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, rangeStr := range privateRanges {
		if nm.ipInRange(ip, rangeStr) {
			return true
		}
	}

	return false
}

func (nm *NetworkMonitor) ipInRange(ip, rangeStr string) bool {
	// Simple implementation - in production use proper IP range checking
	return strings.HasPrefix(ip, strings.Split(rangeStr, "/")[0][:strings.LastIndex(strings.Split(rangeStr, "/")[0], ".")])
}

func (nm *NetworkMonitor) getProcessName(processID uint32) (string, error) {
	handle, _, err := netProcOpenProcess.Call(
		PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
		0,
		uintptr(processID),
	)

	if handle == 0 {
		return "", fmt.Errorf("failed to open process: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(handle))

	var filename [windows.MAX_PATH]uint16
	ret, _, _ := netProcGetModuleFileNameExW.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&filename[0])),
		windows.MAX_PATH,
	)

	if ret == 0 {
		return "", fmt.Errorf("failed to get module filename")
	}

	return windows.UTF16ToString(filename[:]), nil
}

func (nm *NetworkMonitor) generateConnectionKey(conn *NetworkConnectionInfo) string {
	return fmt.Sprintf("%s:%d-%s:%d-%s", conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort, conn.Protocol)
}

func (nm *NetworkMonitor) generateEventID() string {
	return fmt.Sprintf("network_%d", time.Now().UnixNano())
}

func (nm *NetworkMonitor) ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}

func (nm *NetworkMonitor) portToHostByteOrder(port uint32) uint16 {
	return uint16(port>>8) | uint16(port<<8)
}

func (nm *NetworkMonitor) tcpStateToString(state uint32) string {
	switch state {
	case TCP_ESTABLISHED:
		return "ESTABLISHED"
	case TCP_SYN_SENT:
		return "SYN_SENT"
	case TCP_SYN_RECV:
		return "SYN_RECV"
	case TCP_FIN_WAIT1:
		return "FIN_WAIT1"
	case TCP_FIN_WAIT2:
		return "FIN_WAIT2"
	case TCP_TIME_WAIT:
		return "TIME_WAIT"
	case TCP_CLOSE:
		return "CLOSE"
	case TCP_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case TCP_LAST_ACK:
		return "LAST_ACK"
	case TCP_LISTEN:
		return "LISTEN"
	case TCP_CLOSING:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}
