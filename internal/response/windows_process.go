package response

import (
	"fmt"
	"syscall"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// Windows Process Control Implementation
// Uses Windows API for process termination and control

const (
	// Process access rights
	PROCESS_TERMINATE = 0x0001
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_SUSPEND_RESUME = 0x0800
	
	// Process termination
	PROCESS_TERMINATE_FORCE = 0x0001
	
	// Exit codes
	STILL_ACTIVE = 259
)

var (
	// Windows API functions
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32Process = syscall.NewLazyDLL("user32.dll")
	
	procOpenProcess = kernel32.NewProc("OpenProcess")
	procTerminateProcess = kernel32.NewProc("TerminateProcess")
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
	procEnumProcesses = kernel32.NewProc("EnumProcesses")
	procGetProcessImageFileNameW = kernel32.NewProc("GetProcessImageFileNameW")
	procGetWindowThreadProcessId = user32Process.NewProc("GetWindowThreadProcessId")
)

// WindowsProcessController implements Windows process control
type WindowsProcessController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewWindowsProcessController creates a new Windows process controller
func NewWindowsProcessController(cfg *config.ResponseConfig, logger *utils.Logger) *WindowsProcessController {
	return &WindowsProcessController{
		config: cfg,
		logger: logger,
	}
}

// TerminateProcesses terminates processes by ID
func (wpc *WindowsProcessController) TerminateProcesses(processID int) error {
	wpc.logger.Info("Terminating process: %d", processID)

	// Open process handle
	handle, err := wpc.openProcess(processID, PROCESS_TERMINATE)
	if err != nil {
		return fmt.Errorf("failed to open process %d: %w", processID, err)
	}
	defer syscall.CloseHandle(handle)

	// Terminate process
	success, _, _ := procTerminateProcess.Call(
		uintptr(handle),
		uintptr(1), // Exit code 1
	)

	if success == 0 {
		return fmt.Errorf("failed to terminate process %d", processID)
	}

	wpc.logger.Info("Process %d terminated successfully", processID)
	return nil
}

// TerminateProcessTree terminates a process and all its child processes
func (wpc *WindowsProcessController) TerminateProcessTree(processID int) error {
	wpc.logger.Info("Terminating process tree for: %d", processID)

	// Get child processes
	children, err := wpc.getChildProcesses(processID)
	if err != nil {
		wpc.logger.Warn("Failed to get child processes: %v", err)
	}

	// Terminate child processes first
	for _, childID := range children {
		if err := wpc.TerminateProcesses(childID); err != nil {
			wpc.logger.Warn("Failed to terminate child process %d: %v", childID, err)
		}
	}

	// Terminate parent process
	return wpc.TerminateProcesses(processID)
}

// SuspendProcess suspends a process
func (wpc *WindowsProcessController) SuspendProcess(processID int) error {
	wpc.logger.Info("Suspending process: %d", processID)

	// Open process handle with suspend/resume rights
	handle, err := wpc.openProcess(processID, PROCESS_SUSPEND_RESUME)
	if err != nil {
		return fmt.Errorf("failed to open process %d: %w", processID, err)
	}
	defer syscall.CloseHandle(handle)

	// Suspend process using NtSuspendProcess
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtSuspendProcess := ntdll.NewProc("NtSuspendProcess")
	
	success, _, _ := procNtSuspendProcess.Call(uintptr(handle))
	
	if success != 0 {
		return fmt.Errorf("failed to suspend process %d", processID)
	}

	wpc.logger.Info("Process %d suspended successfully", processID)
	return nil
}

// ResumeProcess resumes a suspended process
func (wpc *WindowsProcessController) ResumeProcess(processID int) error {
	wpc.logger.Info("Resuming process: %d", processID)

	// Open process handle with suspend/resume rights
	handle, err := wpc.openProcess(processID, PROCESS_SUSPEND_RESUME)
	if err != nil {
		return fmt.Errorf("failed to open process %d: %w", processID, err)
	}
	defer syscall.CloseHandle(handle)

	// Resume process using NtResumeProcess
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	procNtResumeProcess := ntdll.NewProc("NtResumeProcess")
	
	success, _, _ := procNtResumeProcess.Call(uintptr(handle))
	
	if success != 0 {
		return fmt.Errorf("failed to resume process %d", processID)
	}

	wpc.logger.Info("Process %d resumed successfully", processID)
	return nil
}

// GetProcessInfo gets information about a process
func (wpc *WindowsProcessController) GetProcessInfo(processID int) (*ProcessInfo, error) {
	// Open process handle with query rights
	handle, err := wpc.openProcess(processID, PROCESS_QUERY_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("failed to open process %d: %w", processID, err)
	}
	defer syscall.CloseHandle(handle)

	// Get process image file name
	fileName, err := wpc.getProcessImageFileName(handle)
	if err != nil {
		wpc.logger.Warn("Failed to get process image file name: %v", err)
		fileName = "unknown"
	}

	// Get process exit code to check if still running
	var exitCode uint32
	success, _, _ := procGetExitCodeProcess.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&exitCode)),
	)

	isRunning := success != 0 && exitCode == STILL_ACTIVE

	info := &ProcessInfo{
		ProcessID:  processID,
		ImageName:  fileName,
		IsRunning:  isRunning,
		ExitCode:   int(exitCode),
	}

	return info, nil
}

// openProcess opens a process handle
func (wpc *WindowsProcessController) openProcess(processID int, desiredAccess uint32) (syscall.Handle, error) {
	handle, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		0, // bInheritHandle
		uintptr(processID),
	)

	if handle == 0 {
		return 0, fmt.Errorf("failed to open process: %v", err)
	}

	return syscall.Handle(handle), nil
}

// getProcessImageFileName gets the image file name of a process
func (wpc *WindowsProcessController) getProcessImageFileName(handle syscall.Handle) (string, error) {
	var fileName [syscall.MAX_PATH]uint16
	
	length, _, err := procGetProcessImageFileNameW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&fileName[0])),
		uintptr(syscall.MAX_PATH),
	)

	if length == 0 {
		return "", fmt.Errorf("failed to get process image file name: %v", err)
	}

	return syscall.UTF16ToString(fileName[:length]), nil
}

// getChildProcesses gets child processes of a given process
func (wpc *WindowsProcessController) getChildProcesses(parentID int) ([]int, error) {
	// This is a simplified implementation
	// In a real system, you would enumerate all processes and check parent-child relationships
	var children []int
	
	// For now, return empty list
	// TODO: Implement proper child process enumeration
	wpc.logger.Debug("Child process enumeration not implemented")
	
	return children, nil
}

// ProcessInfo contains information about a process
type ProcessInfo struct {
	ProcessID int    `json:"process_id"`
	ImageName string `json:"image_name"`
	IsRunning bool   `json:"is_running"`
	ExitCode  int    `json:"exit_code"`
}

// Start initializes the Windows process controller
func (wpc *WindowsProcessController) Start() error {
	wpc.logger.Info("Windows Process Controller started")
	return nil
}

// Stop stops the Windows process controller
func (wpc *WindowsProcessController) Stop() {
	wpc.logger.Info("Windows Process Controller stopped")
} 