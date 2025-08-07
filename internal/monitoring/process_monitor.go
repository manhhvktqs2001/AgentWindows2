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

type ProcessMonitor struct {
	config    *config.ProcessConfig
	logger    *utils.Logger
	eventChan chan models.ProcessEvent
	stopChan  chan bool
	processes map[uint32]*ProcessInfo
	agentID   string // Add agent ID field
}

type ProcessInfo struct {
	ProcessID          uint32
	ParentProcessID    uint32
	Name               string
	CommandLine        string
	ExecutablePath     string
	WorkingDir         string
	UserID             string
	SessionID          uint32
	IntegrityLevel     string
	StartTime          time.Time
	NetworkConnections []NetworkConnection
}

type NetworkConnection struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	Protocol   string
	State      string
}

const (
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_VM_READ                   = 0x0010
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	PROCESS_CREATE_PROCESS  = 0x0080
	PROCESS_CREATE_THREAD   = 0x0002
	PROCESS_VM_OPERATION    = 0x0008
	PROCESS_VM_WRITE        = 0x0020
	PROCESS_DUP_HANDLE      = 0x0040
	PROCESS_SET_INFORMATION = 0x0200
	PROCESS_SET_QUOTA       = 0x0100
	PROCESS_SUSPEND_RESUME  = 0x0800
	PROCESS_TERMINATE       = 0x0001
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	psapi    = windows.NewLazySystemDLL("psapi.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procGetModuleFileNameExW = psapi.NewProc("GetModuleFileNameExW")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	procGetCurrentProcessId  = kernel32.NewProc("GetCurrentProcessId")
	procGetProcessId         = kernel32.NewProc("GetProcessId")
	procGetProcessTimes      = kernel32.NewProc("GetProcessTimes")
	procGetExitCodeProcess   = kernel32.NewProc("GetExitCodeProcess")
)

func NewProcessMonitor(cfg *config.ProcessConfig, logger *utils.Logger) *ProcessMonitor {
	return &ProcessMonitor{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.ProcessEvent, 1000),
		stopChan:  make(chan bool),
		processes: make(map[uint32]*ProcessInfo),
		agentID:   "", // Will be set later
	}
}

// Start begins process monitoring
func (pm *ProcessMonitor) Start() error {
	pm.logger.Info("Starting process monitor...")

	// Initialize process list
	pm.processes = make(map[uint32]*ProcessInfo)

	// Get initial process list
	if err := pm.enumerateProcesses(); err != nil {
		return fmt.Errorf("failed to enumerate initial processes: %w", err)
	}

	// Start monitoring goroutine
	go pm.monitorProcesses()

	pm.logger.Info("Process monitor started successfully")
	return nil
}

// Stop stops process monitoring
func (pm *ProcessMonitor) Stop() {
	pm.logger.Info("Stopping process monitor...")
	close(pm.stopChan)
	close(pm.eventChan)
	pm.logger.Info("Process monitor stopped")
}

// GetEventChannel returns the channel for process events
func (pm *ProcessMonitor) GetEventChannel() <-chan models.ProcessEvent {
	return pm.eventChan
}

// SetAgentID sets the agent ID for events
func (pm *ProcessMonitor) SetAgentID(agentID string) {
	pm.agentID = agentID
}

// enumerateProcesses gets the current list of running processes
func (pm *ProcessMonitor) enumerateProcesses() error {
	// Use Windows API to enumerate processes
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer windows.CloseHandle(handle)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Get first process
	if err := windows.Process32First(handle, &pe32); err != nil {
		return fmt.Errorf("failed to get first process: %w", err)
	}

	// Enumerate all processes
	for {
		processInfo := &ProcessInfo{
			ProcessID:       pe32.ProcessID,
			ParentProcessID: pe32.ParentProcessID,
			Name:            windows.UTF16ToString(pe32.ExeFile[:]),
		}

		pm.processes[pe32.ProcessID] = processInfo

		// Get next process
		if err := windows.Process32Next(handle, &pe32); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return fmt.Errorf("failed to get next process: %w", err)
		}
	}

	return nil
}

// monitorProcesses continuously monitors for new processes
func (pm *ProcessMonitor) monitorProcesses() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopChan:
			return
		case <-ticker.C:
			if err := pm.checkNewProcesses(); err != nil {
				pm.logger.Error("Failed to check new processes: %v", err)
			}
		}
	}
}

// checkNewProcesses checks for new processes and creates events
func (pm *ProcessMonitor) checkNewProcesses() error {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("failed to create process snapshot: %w", err)
	}
	defer windows.CloseHandle(handle)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	if err := windows.Process32First(handle, &pe32); err != nil {
		return fmt.Errorf("failed to get first process: %w", err)
	}

	for {
		processID := pe32.ProcessID
		processName := windows.UTF16ToString(pe32.ExeFile[:])

		// Check if this is a new process
		if _, exists := pm.processes[processID]; !exists {
			// New process detected
			pm.handleNewProcess(processID, pe32.ParentProcessID, processName)
		}

		if err := windows.Process32Next(handle, &pe32); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return fmt.Errorf("failed to get next process: %w", err)
		}
	}

	return nil
}

// handleNewProcess creates an event for a new process
func (pm *ProcessMonitor) handleNewProcess(processID, parentProcessID uint32, processName string) {
	// Skip excluded processes
	if pm.isExcludedProcess(processName) {
		return
	}

	// Get detailed process information
	processInfo, err := pm.getProcessInfo(processID)
	if err != nil {
		pm.logger.Warn("Failed to get process info for %s (PID: %d): %v", processName, processID, err)
		return
	}

	// Create process event
	event := models.ProcessEvent{
		Event: models.Event{
			ID:          pm.generateEventID(),
			AgentID:     pm.agentID, // Set agent ID
			EventType:   "process_event",
			Timestamp:   time.Now(),
			Severity:    pm.determineProcessSeverity(processName, processInfo),
			Category:    "process",
			Source:      "process_monitor",
			ProcessID:   int(processID),
			ProcessName: processName,
		},
		ParentProcessID:   int(parentProcessID),
		ParentProcessName: pm.getProcessName(parentProcessID),
		CommandLine:       processInfo.CommandLine,
		WorkingDirectory:  processInfo.WorkingDir,
		UserID:            processInfo.UserID,
		SessionID:         int(processInfo.SessionID),
		IntegrityLevel:    processInfo.IntegrityLevel,
	}

	// Send event
	select {
	case pm.eventChan <- event:
		pm.logger.Debug("Process event: %s (PID: %d)", processName, processID)
	default:
		pm.logger.Warn("Event channel full, dropping process event")
	}

	// Update process list
	pm.processes[processID] = &ProcessInfo{
		ProcessID:       processID,
		ParentProcessID: parentProcessID,
		Name:            processName,
	}
}

// getProcessInfo gets detailed information about a process
func (pm *ProcessMonitor) getProcessInfo(processID uint32) (*ProcessInfo, error) {
	// Try with limited information first (for system processes)
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		processID,
	)
	if err != nil {
		// If limited access fails, try with full access
		handle, err = windows.OpenProcess(
			windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
			false,
			processID,
		)
		if err != nil {
			pm.logger.Warn("Failed to get process info for %s (PID: %d): %v", pm.getProcessName(processID), processID, err)
			return nil, fmt.Errorf("failed to open process: %w", err)
		}
	}
	defer windows.CloseHandle(handle)

	processInfo := &ProcessInfo{
		ProcessID: processID,
	}

	// Get executable path
	if path, err := pm.getProcessExecutablePath(handle); err == nil {
		processInfo.ExecutablePath = path
	}

	// Get command line
	if cmdline, err := pm.getProcessCommandLine(handle); err == nil {
		processInfo.CommandLine = cmdline
	}

	// Get working directory
	if workdir, err := pm.getProcessWorkingDirectory(handle); err == nil {
		processInfo.WorkingDir = workdir
	}

	// Get user ID
	if userID, err := pm.getProcessUserID(handle); err == nil {
		processInfo.UserID = userID
	}

	// Get session ID
	if sessionID, err := pm.getProcessSessionID(handle); err == nil {
		processInfo.SessionID = sessionID
	}

	// Get integrity level
	if integrityLevel, err := pm.getProcessIntegrityLevel(handle); err == nil {
		processInfo.IntegrityLevel = integrityLevel
	}

	return processInfo, nil
}

// Helper functions for getting process information
func (pm *ProcessMonitor) getProcessExecutablePath(handle windows.Handle) (string, error) {
	// Implementation would use GetModuleFileNameEx
	return "", nil // Placeholder
}

func (pm *ProcessMonitor) getProcessCommandLine(handle windows.Handle) (string, error) {
	// Implementation would use NtQueryInformationProcess
	return "", nil // Placeholder
}

func (pm *ProcessMonitor) getProcessWorkingDirectory(handle windows.Handle) (string, error) {
	// Implementation would use GetCurrentDirectory
	return "", nil // Placeholder
}

func (pm *ProcessMonitor) getProcessUserID(handle windows.Handle) (string, error) {
	// Implementation would use GetTokenInformation
	return "", nil // Placeholder
}

func (pm *ProcessMonitor) getProcessSessionID(handle windows.Handle) (uint32, error) {
	// Implementation would use ProcessIdToSessionId
	return 0, nil // Placeholder
}

func (pm *ProcessMonitor) getProcessIntegrityLevel(handle windows.Handle) (string, error) {
	// Implementation would use GetTokenInformation with TokenIntegrityLevel
	return "Medium", nil // Placeholder
}

func (pm *ProcessMonitor) getProcessName(processID uint32) string {
	if processInfo, exists := pm.processes[processID]; exists {
		return processInfo.Name
	}
	return "Unknown"
}

func (pm *ProcessMonitor) isExcludedProcess(processName string) bool {
	for _, excludedName := range pm.config.ExcludeNames {
		if strings.EqualFold(processName, excludedName) {
			return true
		}
	}
	return false
}

func (pm *ProcessMonitor) determineProcessSeverity(processName string, processInfo *ProcessInfo) string {
	// High severity for suspicious processes
	if pm.isSuspiciousProcess(processName) {
		return "high"
	}

	// Medium severity for system processes
	if pm.isSystemProcess(processName) {
		return "medium"
	}

	// Low severity for normal processes
	return "low"
}

func (pm *ProcessMonitor) isSuspiciousProcess(processName string) bool {
	suspiciousNames := []string{
		"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
		"reg.exe", "netsh.exe", "net.exe", "sc.exe",
	}

	for _, name := range suspiciousNames {
		if strings.EqualFold(processName, name) {
			return true
		}
	}
	return false
}

func (pm *ProcessMonitor) isSystemProcess(processName string) bool {
	systemNames := []string{
		"svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe",
		"wininit.exe", "services.exe", "spoolsv.exe",
	}

	for _, name := range systemNames {
		if strings.EqualFold(processName, name) {
			return true
		}
	}
	return false
}

func (pm *ProcessMonitor) generateEventID() string {
	return fmt.Sprintf("process_%d", time.Now().UnixNano())
}
