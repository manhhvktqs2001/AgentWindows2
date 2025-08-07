package monitoring

import (
	"fmt"
	"strings"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type BehaviorAnalyzer struct {
	config    *config.BehaviorConfig
	logger    *utils.Logger
	eventChan chan models.BehaviorEvent
	stopChan  chan bool
	agentID   string

	// Behavior tracking
	processBehaviors map[uint32]*ProcessBehavior
	fileBehaviors    map[string]*FileBehavior
	networkBehaviors map[string]*NetworkBehavior
}

type ProcessBehavior struct {
	ProcessID       uint32
	ProcessName     string
	StartTime       time.Time
	CommandLine     string
	ExecutablePath  string
	ParentProcessID uint32
	ChildProcesses  []uint32
	FileOperations  []FileOperation
	NetworkConnections []BehaviorNetworkConnection
	RegistryAccess  []RegistryAccess
	MemoryOperations []MemoryOperation
	ThreatScore     float64
	LastUpdated     time.Time
}

type FileOperation struct {
	FilePath   string
	Operation  string // create, modify, delete, access
	Timestamp  time.Time
	FileSize   int64
	FileHash   string
	UserID     string
}

type BehaviorNetworkConnection struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Protocol   string
	Direction  string // inbound, outbound
	Timestamp  time.Time
	BytesSent  int64
	BytesReceived int64
}

type RegistryAccess struct {
	KeyPath    string
	ValueName  string
	Operation  string // read, write, delete
	Timestamp  time.Time
	OldValue   string
	NewValue   string
}

type MemoryOperation struct {
	Operation  string // allocation, protection, execution
	Address    uintptr
	Size       uintptr
	Protection uint32
	Timestamp  time.Time
}

type FileBehavior struct {
	FilePath      string
	AccessCount   int
	ModifyCount   int
	DeleteCount   int
	FirstSeen     time.Time
	LastSeen      time.Time
	FileSize      int64
	FileHash      string
	ThreatScore   float64
}

type NetworkBehavior struct {
	RemoteIP      string
	RemotePort    uint16
	Protocol      string
	ConnectionCount int
	BytesSent     int64
	BytesReceived int64
	FirstSeen     time.Time
	LastSeen      time.Time
	ThreatScore   float64
}

// Behavior event model
type BehaviorEvent struct {
	AgentID       string                 `json:"agent_id"`
	EventType     string                 `json:"event_type"`
	Timestamp     time.Time              `json:"timestamp"`
	ProcessID     uint32                 `json:"process_id"`
	ProcessName   string                 `json:"process_name"`
	BehaviorType  string                 `json:"behavior_type"`
	ThreatScore   float64                `json:"threat_score"`
	Description   string                 `json:"description"`
	Data          map[string]interface{} `json:"data"`
}

func (e *BehaviorEvent) GetType() string {
	return e.EventType
}

func (e *BehaviorEvent) GetTimestamp() time.Time {
	return e.Timestamp
}

func (e *BehaviorEvent) GetAgentID() string {
	return e.AgentID
}

func (e *BehaviorEvent) ToJSON() []byte {
	// Implementation for JSON serialization
	return nil
}

func NewBehaviorAnalyzer(cfg *config.BehaviorConfig, logger *utils.Logger) *BehaviorAnalyzer {
	return &BehaviorAnalyzer{
		config:          cfg,
		logger:          logger,
		eventChan:       make(chan models.BehaviorEvent, 100),
		stopChan:        make(chan bool),
		processBehaviors: make(map[uint32]*ProcessBehavior),
		fileBehaviors:    make(map[string]*FileBehavior),
		networkBehaviors: make(map[string]*NetworkBehavior),
	}
}

func (b *BehaviorAnalyzer) SetAgentID(agentID string) {
	b.agentID = agentID
}

func (b *BehaviorAnalyzer) Start() error {
	if !b.config.Enabled {
		b.logger.Info("Behavior analyzer disabled")
		return nil
	}

	b.logger.Info("Starting behavior analyzer...")

	go b.analysisWorker()

	return nil
}

func (b *BehaviorAnalyzer) Stop() {
	if !b.config.Enabled {
		return
	}

	b.logger.Info("Stopping behavior analyzer...")
	close(b.stopChan)
}

func (b *BehaviorAnalyzer) GetEventChannel() chan models.BehaviorEvent {
	return b.eventChan
}

func (b *BehaviorAnalyzer) analysisWorker() {
	ticker := time.NewTicker(time.Duration(b.config.AnalysisInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopChan:
			return
		case <-ticker.C:
			b.performBehaviorAnalysis()
		}
	}
}

func (b *BehaviorAnalyzer) performBehaviorAnalysis() {
	// Analyze process behaviors
	b.analyzeProcessBehaviors()

	// Analyze file behaviors
	b.analyzeFileBehaviors()

	// Analyze network behaviors
	b.analyzeNetworkBehaviors()

	// Clean up old data
	b.cleanupOldData()
}

func (b *BehaviorAnalyzer) analyzeProcessBehaviors() {
	for processID, behavior := range b.processBehaviors {
		threatScore := b.calculateProcessThreatScore(behavior)
		behavior.ThreatScore = threatScore
		behavior.LastUpdated = time.Now()

		if threatScore > b.config.ThreatThreshold {
			event := models.BehaviorEvent{
				Event: models.Event{
					AgentID:   b.agentID,
					EventType: "behavior_analysis",
					Timestamp: time.Now(),
					Severity:  "high",
					Category:  "behavior_analysis",
					Source:    "behavior_analyzer",
					Data: map[string]interface{}{
						"behavior": behavior,
						"analysis": b.getProcessAnalysis(behavior),
					},
				},
				ProcessID:    processID,
				ProcessName:  behavior.ProcessName,
				BehaviorType: "process_behavior",
				ThreatScore:  threatScore,
				Description:  b.generateProcessDescription(behavior),
			}

			select {
			case b.eventChan <- event:
				b.logger.Info("Behavior analysis event sent for process %s (PID: %d, Score: %.2f)", 
					behavior.ProcessName, processID, threatScore)
			default:
				b.logger.Warn("Behavior event channel full, dropping event")
			}
		}
	}
}

func (b *BehaviorAnalyzer) analyzeFileBehaviors() {
	for filePath, behavior := range b.fileBehaviors {
		threatScore := b.calculateFileThreatScore(behavior)
		behavior.ThreatScore = threatScore

		if threatScore > b.config.ThreatThreshold {
			event := models.BehaviorEvent{
				Event: models.Event{
					AgentID:   b.agentID,
					EventType: "behavior_analysis",
					Timestamp: time.Now(),
					Severity:  "high",
					Category:  "behavior_analysis",
					Source:    "behavior_analyzer",
					Data: map[string]interface{}{
						"behavior": behavior,
						"analysis": b.getFileAnalysis(behavior),
					},
				},
				ProcessID:    0, // File behavior doesn't have specific process
				ProcessName:  "file_system",
				BehaviorType: "file_behavior",
				ThreatScore:  threatScore,
				Description:  b.generateFileDescription(behavior),
			}

			select {
			case b.eventChan <- event:
				b.logger.Info("File behavior analysis event sent for %s (Score: %.2f)", 
					filePath, threatScore)
			default:
				b.logger.Warn("Behavior event channel full, dropping event")
			}
		}
	}
}

func (b *BehaviorAnalyzer) analyzeNetworkBehaviors() {
	for networkKey, behavior := range b.networkBehaviors {
		threatScore := b.calculateNetworkThreatScore(behavior)
		behavior.ThreatScore = threatScore

		if threatScore > b.config.ThreatThreshold {
			event := models.BehaviorEvent{
				Event: models.Event{
					AgentID:   b.agentID,
					EventType: "behavior_analysis",
					Timestamp: time.Now(),
					Severity:  "high",
					Category:  "behavior_analysis",
					Source:    "behavior_analyzer",
					Data: map[string]interface{}{
						"behavior": behavior,
						"analysis": b.getNetworkAnalysis(behavior),
					},
				},
				ProcessID:    0, // Network behavior doesn't have specific process
				ProcessName:  "network",
				BehaviorType: "network_behavior",
				ThreatScore:  threatScore,
				Description:  b.generateNetworkDescription(behavior),
			}

			select {
			case b.eventChan <- event:
				b.logger.Info("Network behavior analysis event sent for %s (Score: %.2f)", 
					networkKey, threatScore)
			default:
				b.logger.Warn("Behavior event channel full, dropping event")
			}
		}
	}
}

func (b *BehaviorAnalyzer) calculateProcessThreatScore(behavior *ProcessBehavior) float64 {
	score := 0.0

	// Check for suspicious process creation patterns
	if len(behavior.ChildProcesses) > b.config.MaxChildProcesses {
		score += 0.3
	}

	// Check for file operations
	if len(behavior.FileOperations) > b.config.MaxFileOperations {
		score += 0.2
	}

	// Check for network connections
	if len(behavior.NetworkConnections) > b.config.MaxNetworkConnections {
		score += 0.2
	}

	// Check for registry access
	if len(behavior.RegistryAccess) > b.config.MaxRegistryAccess {
		score += 0.2
	}

	// Check for memory operations
	if len(behavior.MemoryOperations) > b.config.MaxMemoryOperations {
		score += 0.3
	}

	// Check for suspicious command line
	if b.isSuspiciousCommandLine(behavior.CommandLine) {
		score += 0.4
	}

	// Check for process age
	age := time.Since(behavior.StartTime)
	if age < time.Minute*5 {
		score += 0.2 // New process
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (b *BehaviorAnalyzer) calculateFileThreatScore(behavior *FileBehavior) float64 {
	score := 0.0

	// Check for high access frequency
	if behavior.AccessCount > b.config.MaxFileAccess {
		score += 0.3
	}

	// Check for rapid modifications
	if behavior.ModifyCount > b.config.MaxFileModifications {
		score += 0.4
	}

	// Check for file age
	age := time.Since(behavior.FirstSeen)
	if age < time.Minute*10 {
		score += 0.2 // New file
	}

	// Check for suspicious file extensions
	if b.isSuspiciousFileExtension(behavior.FilePath) {
		score += 0.3
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (b *BehaviorAnalyzer) calculateNetworkThreatScore(behavior *NetworkBehavior) float64 {
	score := 0.0

	// Check for high connection frequency
	if behavior.ConnectionCount > b.config.MaxNetworkConnections {
		score += 0.3
	}

	// Check for large data transfer
	if behavior.BytesSent > b.config.MaxBytesSent || behavior.BytesReceived > b.config.MaxBytesReceived {
		score += 0.4
	}

	// Check for suspicious ports
	if b.isSuspiciousPort(behavior.RemotePort) {
		score += 0.3
	}

	// Check for connection age
	age := time.Since(behavior.FirstSeen)
	if age < time.Minute*5 {
		score += 0.2 // New connection
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	return score
}

func (b *BehaviorAnalyzer) isSuspiciousCommandLine(cmdline string) bool {
	suspiciousPatterns := []string{
		"powershell -enc",
		"cmd /c",
		"wmic",
		"reg add",
		"schtasks",
		"at ",
		"sc ",
		"net ",
		"rundll32",
		"regsvr32",
	}

	cmdlineLower := strings.ToLower(cmdline)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(cmdlineLower, pattern) {
			return true
		}
	}

	return false
}

func (b *BehaviorAnalyzer) isSuspiciousFileExtension(filePath string) bool {
	suspiciousExtensions := []string{
		".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
		".scr", ".pif", ".com", ".hta", ".jar", ".msi",
	}

	filePathLower := strings.ToLower(filePath)
	for _, ext := range suspiciousExtensions {
		if strings.HasSuffix(filePathLower, ext) {
			return true
		}
	}

	return false
}

func (b *BehaviorAnalyzer) isSuspiciousPort(port uint16) bool {
	suspiciousPorts := []uint16{
		22, 23, 3389, 5900, 5901, 5902, 5903, 5904, 5905,
		8080, 8443, 4444, 4443, 4442, 4441, 4440,
	}

	for _, suspiciousPort := range suspiciousPorts {
		if port == suspiciousPort {
			return true
		}
	}

	return false
}

func (b *BehaviorAnalyzer) generateProcessDescription(behavior *ProcessBehavior) string {
	description := fmt.Sprintf("Suspicious behavior detected for process %s (PID: %d)", 
		behavior.ProcessName, behavior.ProcessID)

	if len(behavior.ChildProcesses) > 0 {
		description += fmt.Sprintf(", created %d child processes", len(behavior.ChildProcesses))
	}

	if len(behavior.FileOperations) > 0 {
		description += fmt.Sprintf(", performed %d file operations", len(behavior.FileOperations))
	}

	if len(behavior.NetworkConnections) > 0 {
		description += fmt.Sprintf(", established %d network connections", len(behavior.NetworkConnections))
	}

	return description
}

func (b *BehaviorAnalyzer) generateFileDescription(behavior *FileBehavior) string {
	return fmt.Sprintf("Suspicious file behavior detected for %s: %d accesses, %d modifications", 
		behavior.FilePath, behavior.AccessCount, behavior.ModifyCount)
}

func (b *BehaviorAnalyzer) generateNetworkDescription(behavior *NetworkBehavior) string {
	return fmt.Sprintf("Suspicious network behavior detected: %d connections to %s:%d, %d bytes transferred", 
		behavior.ConnectionCount, behavior.RemoteIP, behavior.RemotePort, 
		behavior.BytesSent+behavior.BytesReceived)
}

func (b *BehaviorAnalyzer) getProcessAnalysis(behavior *ProcessBehavior) map[string]interface{} {
	return map[string]interface{}{
		"child_processes": len(behavior.ChildProcesses),
		"file_operations": len(behavior.FileOperations),
		"network_connections": len(behavior.NetworkConnections),
		"registry_access": len(behavior.RegistryAccess),
		"memory_operations": len(behavior.MemoryOperations),
		"process_age": time.Since(behavior.StartTime).String(),
		"suspicious_cmdline": b.isSuspiciousCommandLine(behavior.CommandLine),
	}
}

func (b *BehaviorAnalyzer) getFileAnalysis(behavior *FileBehavior) map[string]interface{} {
	return map[string]interface{}{
		"access_count": behavior.AccessCount,
		"modify_count": behavior.ModifyCount,
		"delete_count": behavior.DeleteCount,
		"file_age": time.Since(behavior.FirstSeen).String(),
		"file_size": behavior.FileSize,
		"suspicious_extension": b.isSuspiciousFileExtension(behavior.FilePath),
	}
}

func (b *BehaviorAnalyzer) getNetworkAnalysis(behavior *NetworkBehavior) map[string]interface{} {
	return map[string]interface{}{
		"connection_count": behavior.ConnectionCount,
		"bytes_sent": behavior.BytesSent,
		"bytes_received": behavior.BytesReceived,
		"connection_age": time.Since(behavior.FirstSeen).String(),
		"suspicious_port": b.isSuspiciousPort(behavior.RemotePort),
	}
}

func (b *BehaviorAnalyzer) cleanupOldData() {
	cutoff := time.Now().Add(-time.Duration(b.config.DataRetention) * time.Hour)

	// Clean up old process behaviors
	for processID, behavior := range b.processBehaviors {
		if behavior.LastUpdated.Before(cutoff) {
			delete(b.processBehaviors, processID)
		}
	}

	// Clean up old file behaviors
	for filePath, behavior := range b.fileBehaviors {
		if behavior.LastSeen.Before(cutoff) {
			delete(b.fileBehaviors, filePath)
		}
	}

	// Clean up old network behaviors
	for networkKey, behavior := range b.networkBehaviors {
		if behavior.LastSeen.Before(cutoff) {
			delete(b.networkBehaviors, networkKey)
		}
	}
}

// Public methods for other components to update behavior data
func (b *BehaviorAnalyzer) UpdateProcessBehavior(processID uint32, processName string, operation string, data interface{}) {
	behavior, exists := b.processBehaviors[processID]
	if !exists {
		behavior = &ProcessBehavior{
			ProcessID:   processID,
			ProcessName: processName,
			StartTime:   time.Now(),
		}
		b.processBehaviors[processID] = behavior
	}

	behavior.LastUpdated = time.Now()

	switch operation {
	case "file_operation":
		if fileOp, ok := data.(FileOperation); ok {
			behavior.FileOperations = append(behavior.FileOperations, fileOp)
		}
	case "network_connection":
		if netConn, ok := data.(BehaviorNetworkConnection); ok {
			behavior.NetworkConnections = append(behavior.NetworkConnections, netConn)
		}
	case "registry_access":
		if regAccess, ok := data.(RegistryAccess); ok {
			behavior.RegistryAccess = append(behavior.RegistryAccess, regAccess)
		}
	case "memory_operation":
		if memOp, ok := data.(MemoryOperation); ok {
			behavior.MemoryOperations = append(behavior.MemoryOperations, memOp)
		}
	case "child_process":
		if childPID, ok := data.(uint32); ok {
			behavior.ChildProcesses = append(behavior.ChildProcesses, childPID)
		}
	}
}

func (b *BehaviorAnalyzer) UpdateFileBehavior(filePath string, operation string, data interface{}) {
	behavior, exists := b.fileBehaviors[filePath]
	if !exists {
		behavior = &FileBehavior{
			FilePath:  filePath,
			FirstSeen: time.Now(),
		}
		b.fileBehaviors[filePath] = behavior
	}

	behavior.LastSeen = time.Now()

	switch operation {
	case "access":
		behavior.AccessCount++
	case "modify":
		behavior.ModifyCount++
	case "delete":
		behavior.DeleteCount++
	}

	if fileSize, ok := data.(int64); ok {
		behavior.FileSize = fileSize
	}
}

func (b *BehaviorAnalyzer) UpdateNetworkBehavior(remoteIP string, remotePort uint16, protocol string, data interface{}) {
	networkKey := fmt.Sprintf("%s:%d:%s", remoteIP, remotePort, protocol)
	
	behavior, exists := b.networkBehaviors[networkKey]
	if !exists {
		behavior = &NetworkBehavior{
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			Protocol:   protocol,
			FirstSeen:  time.Now(),
		}
		b.networkBehaviors[networkKey] = behavior
	}

	behavior.LastSeen = time.Now()
	behavior.ConnectionCount++

	if netData, ok := data.(map[string]interface{}); ok {
		if bytesSent, ok := netData["bytes_sent"].(int64); ok {
			behavior.BytesSent += bytesSent
		}
		if bytesReceived, ok := netData["bytes_received"].(int64); ok {
			behavior.BytesReceived += bytesReceived
		}
	}
} 