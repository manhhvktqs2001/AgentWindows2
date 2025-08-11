// internal/monitoring/process_monitor.go - Fixed version to prevent system freeze

package monitoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	agentID   string

	// Safety mechanisms
	isShuttingDown bool
	mu             sync.RWMutex
	rateLimiter    map[uint32]time.Time
	rateMu         sync.Mutex
	scanInterval   time.Duration
	ctx            context.Context
	cancel         context.CancelFunc

	// Prevent sends to a closed channel
	eventClosed int32
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

	// Reduced permissions to minimize system impact
	SAFE_PROCESS_ACCESS = windows.PROCESS_QUERY_LIMITED_INFORMATION
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procOpenProcess         = kernel32.NewProc("OpenProcess")
	procGetCurrentProcessId = kernel32.NewProc("GetCurrentProcessId")
	procGetProcessId        = kernel32.NewProc("GetProcessId")
)

func NewProcessMonitor(cfg *config.ProcessConfig, logger *utils.Logger) *ProcessMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	// Set safe scan interval
	scanInterval := 10 * time.Second
	if cfg != nil {
		// Don't scan too frequently to avoid system impact
		if scanInterval < 5*time.Second {
			scanInterval = 5 * time.Second
		}
	}

	return &ProcessMonitor{
		config:       cfg,
		logger:       logger,
		eventChan:    make(chan models.ProcessEvent, 500), // Reduced buffer
		stopChan:     make(chan bool, 1),
		processes:    make(map[uint32]*ProcessInfo),
		agentID:      "",
		rateLimiter:  make(map[uint32]time.Time),
		scanInterval: scanInterval,
		ctx:          ctx,
		cancel:       cancel,
	}
}

func (pm *ProcessMonitor) Start() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.isShuttingDown {
		return fmt.Errorf("process monitor is shutting down")
	}

	pm.logger.Info("Starting process monitor with safe settings...")

	// Initialize process list with timeout
	if err := pm.enumerateProcessesSafe(); err != nil {
		pm.logger.Warn("Failed to enumerate initial processes: %v", err)
		// Continue anyway with empty process list
	}

	// Start monitoring with reduced frequency and safety checks
	go pm.monitorProcessesSafe()

	pm.logger.Info("Process monitor started successfully")
	return nil
}

func (pm *ProcessMonitor) Stop() {
	pm.mu.Lock()
	pm.isShuttingDown = true
	pm.mu.Unlock()

	pm.logger.Info("Stopping process monitor...")

	// Cancel context to stop all operations
	pm.cancel()

	// Signal stop
	select {
	case pm.stopChan <- true:
	default:
		// Channel might be full
	}

	// Wait for graceful shutdown with timeout
	done := make(chan bool, 1)
	go func() {
		// Clean up resources
		pm.mu.Lock()
		pm.processes = make(map[uint32]*ProcessInfo)
		pm.mu.Unlock()
		done <- true
	}()

	select {
	case <-done:
		pm.logger.Info("Process monitor stopped gracefully")
	case <-time.After(5 * time.Second):
		pm.logger.Warn("Process monitor shutdown timeout")
	}

	// Mark closed and close channel safely
	if atomic.CompareAndSwapInt32(&pm.eventClosed, 0, 1) {
		close(pm.eventChan)
	}
	pm.logger.Info("Process monitor stopped")
}

func (pm *ProcessMonitor) GetEventChannel() <-chan models.ProcessEvent {
	return pm.eventChan
}

func (pm *ProcessMonitor) SetAgentID(agentID string) {
	pm.agentID = agentID
}

// enumerateProcessesSafe safely enumerates processes with timeout
func (pm *ProcessMonitor) enumerateProcessesSafe() error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				pm.logger.Error("Process enumeration panic: %v", r)
				done <- fmt.Errorf("enumeration panic: %v", r)
			}
		}()
		done <- pm.enumerateProcesses()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("process enumeration timeout")
	case <-pm.ctx.Done():
		return fmt.Errorf("enumeration cancelled")
	}
}

func (pm *ProcessMonitor) enumerateProcesses() error {
	// Use Windows API to enumerate processes safely
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

	processCount := 0
	maxProcesses := 1000 // Limit to prevent memory issues

	// Enumerate processes with limits
	for processCount < maxProcesses {
		// Check for cancellation
		select {
		case <-pm.ctx.Done():
			return fmt.Errorf("enumeration cancelled")
		default:
		}

		// Skip system idle process and other critical processes
		if !pm.shouldSkipProcess(pe32.ProcessID, windows.UTF16ToString(pe32.ExeFile[:])) {
			processInfo := &ProcessInfo{
				ProcessID:       pe32.ProcessID,
				ParentProcessID: pe32.ParentProcessID,
				Name:            windows.UTF16ToString(pe32.ExeFile[:]),
			}
			pm.processes[pe32.ProcessID] = processInfo
			processCount++
		}
		// Get next process
		if err := windows.Process32Next(handle, &pe32); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return fmt.Errorf("failed to get next process: %w", err)
		}
	}

	pm.logger.Info("Enumerated %d processes", processCount)
	return nil
}

// shouldSkipProcess determines if a process should be skipped for safety
func (pm *ProcessMonitor) shouldSkipProcess(processID uint32, processName string) bool {
	// Skip system processes that shouldn't be monitored
	if processID == 0 || processID == 4 {
		return true // System Idle Process and System
	}

	// Skip our own process
	currentPID := uint32(windows.GetCurrentProcessId())
	if processID == currentPID {
		return true
	}

	// Skip critical system processes to prevent system instability
	criticalProcesses := []string{
		"system", "idle", "registry", "smss.exe", "csrss.exe",
		"wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
		"svchost.exe", "dwm.exe", "fontdrvhost.exe",
		"audiodg.exe", "conhost.exe", "taskhostw.exe",
	}

	lowerName := strings.ToLower(processName)
	for _, critical := range criticalProcesses {
		if lowerName == critical {
			return true
		}
	}

	// Skip processes in excluded list
	if pm.config != nil {
		for _, excludedName := range pm.config.ExcludeNames {
			if strings.EqualFold(processName, excludedName) {
				return true
			}
		}
	}

	return false
}

// monitorProcessesSafe safely monitors for new processes
func (pm *ProcessMonitor) monitorProcessesSafe() {
	defer func() {
		if r := recover(); r != nil {
			pm.logger.Error("Process monitoring panic: %v", r)
		}
	}()

	ticker := time.NewTicker(pm.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			pm.logger.Info("Process monitoring cancelled")
			return
		case <-pm.stopChan:
			pm.logger.Info("Process monitoring stop signal received")
			return
		case <-ticker.C:
			pm.checkNewProcessesSafe()
		}
	}
}

// checkNewProcessesSafe checks for new processes with safety measures
func (pm *ProcessMonitor) checkNewProcessesSafe() {
	defer func() {
		if r := recover(); r != nil {
			pm.logger.Error("New process check panic: %v", r)
		}
	}()

	// Check if shutting down
	pm.mu.RLock()
	if pm.isShuttingDown {
		pm.mu.RUnlock()
		return
	}
	pm.mu.RUnlock()

	// Create snapshot with timeout (prevents system freeze)
	snapshotDone := make(chan error, 1)
	var handle windows.Handle

	go func() {
		h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			snapshotDone <- err
			return
		}
		handle = h
		snapshotDone <- nil
	}()

	select {
	case err := <-snapshotDone:
		if err != nil {
			pm.logger.Error("Failed to create process snapshot: %v", err)
			return
		}
	case <-time.After(5 * time.Second):
		pm.logger.Warn("Process snapshot timeout")
		return
	case <-pm.ctx.Done():
		return
	}

	defer windows.CloseHandle(handle)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	// Call Process32First with timeout guard
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- windows.Process32First(handle, &pe32)
	}()

	select {
	case err := <-firstDone:
		if err != nil {
			pm.logger.Error("Failed to get first process: %v", err)
			return
		}
	case <-time.After(2 * time.Second):
		pm.logger.Warn("Process32First timeout")
		return
	case <-pm.ctx.Done():
		return
	}

	newProcesses := 0
	maxNewProcesses := 50 // Limit new processes to check per scan

	// Hard time budget per scan to avoid long blocking loops
	deadline := time.Now().Add(2 * time.Second)
	for newProcesses < maxNewProcesses {
		select {
		case <-pm.ctx.Done():
			return
		default:
		}

		if time.Now().After(deadline) {
			pm.logger.Debug("Process scan time budget reached")
			break
		}

		processID := pe32.ProcessID
		processName := windows.UTF16ToString(pe32.ExeFile[:])

		// Proceed only if we should not skip
		if !pm.shouldSkipProcess(processID, processName) {
			// Check if this is a new process
			pm.mu.RLock()
			_, exists := pm.processes[processID]
			pm.mu.RUnlock()

			if !exists {
				// New process detected - handle with rate limiting
				if pm.shouldRateLimit(processID) {
					pm.logger.Debug("Rate limiting process %s (PID: %d)", processName, processID)
				} else {
					pm.handleNewProcessSafe(processID, pe32.ParentProcessID, processName)
					newProcesses++
				}
			}
		}
		// Guard Process32Next with timeout to avoid hangs
		nextDone := make(chan error, 1)
		go func() { nextDone <- windows.Process32Next(handle, &pe32) }()
		select {
		case err := <-nextDone:
			if err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					break
				}
				pm.logger.Error("Failed to get next process: %v", err)
				return
			}
		case <-time.After(2 * time.Second):
			pm.logger.Warn("Process32Next timeout, stopping this scan cycle")
			return
		case <-pm.ctx.Done():
			return
		}
	}

	// Cleanup old processes from tracking
	pm.cleanupOldProcesses()
}

// shouldRateLimit checks if we should rate limit process handling
func (pm *ProcessMonitor) shouldRateLimit(processID uint32) bool {
	pm.rateMu.Lock()
	defer pm.rateMu.Unlock()

	now := time.Now()
	lastTime, exists := pm.rateLimiter[processID]

	if exists && now.Sub(lastTime) < 1*time.Second {
		return true
	}

	pm.rateLimiter[processID] = now

	// Cleanup old entries
	if len(pm.rateLimiter) > 100 {
		cutoff := now.Add(-5 * time.Minute)
		for pid, timestamp := range pm.rateLimiter {
			if timestamp.Before(cutoff) {
				delete(pm.rateLimiter, pid)
			}
		}
	}

	return false
}

// handleNewProcessSafe safely handles a new process with timeout
func (pm *ProcessMonitor) handleNewProcessSafe(processID, parentProcessID uint32, processName string) {
	defer func() {
		if r := recover(); r != nil {
			pm.logger.Error("New process handling panic: %v", r)
		}
	}()

	// Process with timeout
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				pm.logger.Error("Process info gathering panic: %v", r)
			}
			done <- true
		}()

		pm.handleNewProcess(processID, parentProcessID, processName)
	}()

	select {
	case <-done:
		// Completed successfully
	case <-time.After(3 * time.Second):
		pm.logger.Debug("New process handling timeout for %s (PID: %d)", processName, processID)
	case <-pm.ctx.Done():
		return
	}
}

func (pm *ProcessMonitor) handleNewProcess(processID, parentProcessID uint32, processName string) {
	// Get process information with minimal access rights
	processInfo, err := pm.getProcessInfoSafe(processID)
	if err != nil {
		// Don't log as error for access denied - it's common for system processes
		if !strings.Contains(strings.ToLower(err.Error()), "access") {
			pm.logger.Debug("Failed to get process info for %s (PID: %d): %v", processName, processID, err)
		}

		// Create minimal process info
		processInfo = &ProcessInfo{
			ProcessID:       processID,
			ParentProcessID: parentProcessID,
			Name:            processName,
		}
	}

	// Create process event
	event := models.ProcessEvent{
		Event: models.Event{
			ID:          pm.generateEventID(),
			AgentID:     pm.agentID,
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

	pm.trySendEvent(event, processName, processID)

	// Update process list
	pm.mu.Lock()
	pm.processes[processID] = processInfo
	pm.mu.Unlock()
}

// getProcessInfoSafe gets process information with minimal access and timeout
func (pm *ProcessMonitor) getProcessInfoSafe(processID uint32) (*ProcessInfo, error) {
	// Try with minimal access rights first
	handle, err := pm.openProcessSafe(processID, SAFE_PROCESS_ACCESS)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)

	processInfo := &ProcessInfo{
		ProcessID: processID,
	}

	// Only try to get basic information to avoid system impact
	// Most detailed info gathering is removed to prevent system locks

	return processInfo, nil
}

// openProcessSafe safely opens a process handle with timeout
func (pm *ProcessMonitor) openProcessSafe(processID uint32, desiredAccess uint32) (windows.Handle, error) {
	type result struct {
		handle windows.Handle
		err    error
	}

	done := make(chan result, 1)
	go func() {
		handle, _, err := procOpenProcess.Call(
			uintptr(desiredAccess),
			0,
			uintptr(processID),
		)

		if handle == 0 {
			done <- result{0, fmt.Errorf("failed to open process: %v", err)}
		} else {
			done <- result{windows.Handle(handle), nil}
		}
	}()

	select {
	case res := <-done:
		return res.handle, res.err
	case <-time.After(2 * time.Second):
		return 0, fmt.Errorf("process open timeout")
	case <-pm.ctx.Done():
		return 0, fmt.Errorf("operation cancelled")
	}
}

// cleanupOldProcesses removes terminated processes from tracking
func (pm *ProcessMonitor) cleanupOldProcesses() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Limit cleanup to prevent long locks
	if len(pm.processes) < 100 {
		return
	}

	// Remove a portion of old processes each cleanup cycle
	count := 0
	maxCleanup := 20

	for processID := range pm.processes {
		if count >= maxCleanup {
			break
		}

		// Check if process still exists (simplified check)
		handle, err := pm.openProcessSafe(processID, SAFE_PROCESS_ACCESS)
		if err != nil {
			// Process likely terminated
			delete(pm.processes, processID)
			count++
		} else {
			windows.CloseHandle(handle)
		}
	}

	if count > 0 {
		pm.logger.Debug("Cleaned up %d terminated processes", count)
	}
}

func (pm *ProcessMonitor) getProcessName(processID uint32) string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if processInfo, exists := pm.processes[processID]; exists {
		return processInfo.Name
	}
	return "Unknown"
}

func (pm *ProcessMonitor) determineProcessSeverity(processName string, processInfo *ProcessInfo) string {
	if pm.isSuspiciousProcess(processName) {
		return "high"
	}
	if pm.isSystemProcess(processName) {
		return "medium"
	}
	return "low"
}

// trySendEvent attempts to send without panicking if channel is closed
func (pm *ProcessMonitor) trySendEvent(event models.ProcessEvent, processName string, processID uint32) {
	if atomic.LoadInt32(&pm.eventClosed) == 1 || pm.isShuttingDown {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// Channel might be closed; ignore to avoid crash
		}
	}()

	select {
	case pm.eventChan <- event:
		pm.logger.Debug("Process event: %s (PID: %d)", processName, processID)
	case <-time.After(1 * time.Second):
		pm.logger.Debug("Process event timeout: %s (PID: %d)", processName, processID)
	default:
		pm.logger.Debug("Process event channel full: %s (PID: %d)", processName, processID)
	}
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
