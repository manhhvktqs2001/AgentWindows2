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

type MemoryScanner struct {
	config    *config.MemoryConfig
	logger    *utils.Logger
	eventChan chan models.MemoryEvent
	stopChan  chan bool
	agentID   string
}

type MemoryRegion struct {
	BaseAddress    uintptr
	RegionSize     uintptr
	Protection     uint32
	State          uint32
	Type           uint32
	IsExecutable   bool
	IsWritable     bool
	IsReadable     bool
	IsPrivate      bool
	IsImage        bool
	IsMapped       bool
}

type MemoryScanResult struct {
	ProcessID     uint32
	ProcessName   string
	RegionCount   int
	SuspiciousRegions []SuspiciousRegion
	ScanTime      time.Duration
	ThreatScore   float64
}

type SuspiciousRegion struct {
	BaseAddress    uintptr
	Size           uintptr
	Protection     uint32
	Reason         string
	ThreatScore    float64
	Patterns       []string
}



// Memory scanner specific constants
const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_FREE    = 0x10000

	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_GUARD             = 0x100
	PAGE_NOCACHE           = 0x200
	PAGE_WRITECOMBINE      = 0x400

	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x100000
)

// Memory scanner specific API functions
var (
	memKernel32 = windows.NewLazySystemDLL("kernel32.dll")
	memPsapi    = windows.NewLazySystemDLL("psapi.dll")

	memProcOpenProcess           = memKernel32.NewProc("OpenProcess")
	memProcVirtualQueryEx        = memKernel32.NewProc("VirtualQueryEx")
	memProcReadProcessMemory     = memKernel32.NewProc("ReadProcessMemory")
	memProcCloseHandle           = memKernel32.NewProc("CloseHandle")
	memProcEnumProcessModules    = memPsapi.NewProc("EnumProcessModules")
	memProcGetModuleInformation = memPsapi.NewProc("GetModuleInformation")
)

type MEMORY_BASIC_INFORMATION struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEINFO struct {
	LPBaseOfDll     uintptr
	SizeOfImage     uint32
	EntryPoint      uintptr
}

func NewMemoryScanner(cfg *config.MemoryConfig, logger *utils.Logger) *MemoryScanner {
	return &MemoryScanner{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.MemoryEvent, 100),
		stopChan:  make(chan bool),
	}
}

func (m *MemoryScanner) SetAgentID(agentID string) {
	m.agentID = agentID
}

func (m *MemoryScanner) Start() error {
	if !m.config.Enabled {
		m.logger.Info("Memory scanner disabled")
		return nil
	}

	m.logger.Info("Starting memory scanner...")

	go m.scanWorker()

	return nil
}

func (m *MemoryScanner) Stop() {
	if !m.config.Enabled {
		return
	}

	m.logger.Info("Stopping memory scanner...")
	close(m.stopChan)
}

func (m *MemoryScanner) GetEventChannel() chan models.MemoryEvent {
	return m.eventChan
}

func (m *MemoryScanner) scanWorker() {
	ticker := time.NewTicker(time.Duration(m.config.ScanInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.performMemoryScan()
		}
	}
}

func (m *MemoryScanner) performMemoryScan() {
	processes, err := m.getRunningProcesses()
	if err != nil {
		m.logger.Error("Failed to get running processes: %v", err)
		return
	}

	for _, process := range processes {
		if m.shouldSkipProcess(process.Name) {
			continue
		}

		scanResult, err := m.scanProcessMemory(process.ProcessID)
		if err != nil {
			m.logger.Debug("Failed to scan process %s (PID: %d): %v", process.Name, process.ProcessID, err)
			continue
		}

		if scanResult.ThreatScore > m.config.ThreatThreshold {
			event := models.MemoryEvent{
				Event: models.Event{
					AgentID:   m.agentID,
					EventType: "memory_scan",
					Timestamp: time.Now(),
					Severity:  "high",
					Category:  "memory_scan",
					Source:    "memory_scanner",
					Data: map[string]interface{}{
						"scan_result": scanResult,
						"threat_score": scanResult.ThreatScore,
					},
				},
				ProcessID:   int(process.ProcessID),
				ProcessName: process.Name,
				Action:      "scan",
				Size:        int64(scanResult.RegionCount),
				Protection:  "suspicious",
			}

			select {
			case m.eventChan <- event:
				m.logger.Info("Memory scan event sent for process %s (PID: %d, Score: %.2f)", 
					process.Name, process.ProcessID, scanResult.ThreatScore)
			default:
				m.logger.Warn("Memory event channel full, dropping event")
			}
		}
	}
}

func (m *MemoryScanner) getRunningProcesses() ([]ProcessInfo, error) {
	// Implementation to get running processes
	// This would use Windows API to enumerate processes
	return []ProcessInfo{}, nil
}

func (m *MemoryScanner) shouldSkipProcess(processName string) bool {
	skipList := []string{
		"System", "Idle", "Registry", "smss.exe", "csrss.exe",
		"wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
		"explorer.exe", "dwm.exe", "taskmgr.exe",
	}

	processNameLower := strings.ToLower(processName)
	for _, skip := range skipList {
		if strings.Contains(processNameLower, strings.ToLower(skip)) {
			return true
		}
	}

	return false
}

func (m *MemoryScanner) scanProcessMemory(processID uint32) (*MemoryScanResult, error) {
	startTime := time.Now()

	// Open process handle
	handle, err := m.openProcessHandle(processID)
	if err != nil {
		return nil, fmt.Errorf("failed to open process handle: %w", err)
	}
	defer m.closeHandle(handle)

	// Get process name
	processName, err := m.getProcessName(processID)
	if err != nil {
		processName = "Unknown"
	}

	// Scan memory regions
	regions, err := m.scanMemoryRegions(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to scan memory regions: %w", err)
	}

	// Analyze suspicious regions
	suspiciousRegions := m.analyzeSuspiciousRegions(regions, handle)

	// Calculate threat score
	threatScore := m.calculateThreatScore(suspiciousRegions)

	scanTime := time.Since(startTime)

	return &MemoryScanResult{
		ProcessID:        processID,
		ProcessName:      processName,
		RegionCount:      len(regions),
		SuspiciousRegions: suspiciousRegions,
		ScanTime:         scanTime,
		ThreatScore:      threatScore,
	}, nil
}

func (m *MemoryScanner) openProcessHandle(processID uint32) (windows.Handle, error) {
	handle, _, err := memProcOpenProcess.Call(
		uintptr(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_OPERATION),
		0,
		uintptr(processID),
	)

	if handle == 0 {
		return 0, fmt.Errorf("failed to open process: %v", err)
	}

	return windows.Handle(handle), nil
}

func (m *MemoryScanner) closeHandle(handle windows.Handle) {
	memProcCloseHandle.Call(uintptr(handle))
}

func (m *MemoryScanner) getProcessName(processID uint32) (string, error) {
	// Implementation to get process name
	return "Unknown", nil
}

func (m *MemoryScanner) scanMemoryRegions(handle windows.Handle) ([]MemoryRegion, error) {
	var regions []MemoryRegion
	var address uintptr = 0

	for {
		var mbi MEMORY_BASIC_INFORMATION
		size, _, err := memProcVirtualQueryEx.Call(
			uintptr(handle),
			address,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)

		if size == 0 {
			break
		}

		if err != nil && err.Error() != "The operation completed successfully." {
			break
		}

		region := MemoryRegion{
			BaseAddress:  mbi.BaseAddress,
			RegionSize:   mbi.RegionSize,
			Protection:   mbi.Protect,
			State:        mbi.State,
			Type:         mbi.Type,
			IsExecutable: m.isExecutable(mbi.Protect),
			IsWritable:   m.isWritable(mbi.Protect),
			IsReadable:   m.isReadable(mbi.Protect),
			IsPrivate:    (mbi.Type & MEM_PRIVATE) != 0,
			IsImage:      (mbi.Type & MEM_IMAGE) != 0,
			IsMapped:     (mbi.Type & MEM_MAPPED) != 0,
		}

		regions = append(regions, region)
		address = mbi.BaseAddress + mbi.RegionSize
	}

	return regions, nil
}

func (m *MemoryScanner) isExecutable(protection uint32) bool {
	return (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0
}

func (m *MemoryScanner) isWritable(protection uint32) bool {
	return (protection & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0
}

func (m *MemoryScanner) isReadable(protection uint32) bool {
	return (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0
}

func (m *MemoryScanner) analyzeSuspiciousRegions(regions []MemoryRegion, handle windows.Handle) []SuspiciousRegion {
	var suspicious []SuspiciousRegion

	for _, region := range regions {
		// Check for RWX memory (highly suspicious)
		if region.IsExecutable && region.IsWritable {
			suspicious = append(suspicious, SuspiciousRegion{
				BaseAddress: region.BaseAddress,
				Size:        region.RegionSize,
				Protection:  region.Protection,
				Reason:      "RWX Memory Region",
				ThreatScore: 0.9,
				Patterns:    []string{"rwx_memory"},
			})
		}

		// Check for private executable memory (suspicious)
		if region.IsExecutable && region.IsPrivate && !region.IsImage {
			suspicious = append(suspicious, SuspiciousRegion{
				BaseAddress: region.BaseAddress,
				Size:        region.RegionSize,
				Protection:  region.Protection,
				Reason:      "Private Executable Memory",
				ThreatScore: 0.7,
				Patterns:    []string{"private_executable"},
			})
		}

		// Check for large executable regions
		if region.IsExecutable && region.RegionSize > 1024*1024 { // > 1MB
			suspicious = append(suspicious, SuspiciousRegion{
				BaseAddress: region.BaseAddress,
				Size:        region.RegionSize,
				Protection:  region.Protection,
				Reason:      "Large Executable Region",
				ThreatScore: 0.5,
				Patterns:    []string{"large_executable"},
			})
		}

		// Check for shellcode patterns
		if m.detectShellcodePatterns(region, handle) {
			suspicious = append(suspicious, SuspiciousRegion{
				BaseAddress: region.BaseAddress,
				Size:        region.RegionSize,
				Protection:  region.Protection,
				Reason:      "Shellcode Pattern Detected",
				ThreatScore: 0.8,
				Patterns:    []string{"shellcode_pattern"},
			})
		}
	}

	return suspicious
}

func (m *MemoryScanner) detectShellcodePatterns(region MemoryRegion, handle windows.Handle) bool {
	// Implementation to detect shellcode patterns
	// This would read memory and look for common shellcode signatures
	return false
}

func (m *MemoryScanner) calculateThreatScore(suspiciousRegions []SuspiciousRegion) float64 {
	if len(suspiciousRegions) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, region := range suspiciousRegions {
		totalScore += region.ThreatScore
	}

	// Normalize score based on number of suspicious regions
	avgScore := totalScore / float64(len(suspiciousRegions))
	
	// Boost score if multiple suspicious regions found
	if len(suspiciousRegions) > 1 {
		avgScore *= float64(len(suspiciousRegions)) * 0.1
	}

	if avgScore > 1.0 {
		avgScore = 1.0
	}

	return avgScore
} 