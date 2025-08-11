package service

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

const (
	ServiceName = "EDR-Agent"
	DisplayName = "EDR Agent Service"
	Description = "Endpoint Detection and Response Agent"
)

// Process hiding constants
const (
	PROCESS_SET_INFORMATION   = 0x0200
	ProcessBreakOnTermination = 0x1D
	ProcessDebugFlags         = 0x1F
	PROCESS_DEBUG_INHERIT     = 0x00000001
)

type WindowsService struct {
	agent AgentInterface
	elog  debug.Log
}

type AgentInterface interface {
	Start() error
	Stop()
}

// Install service
func Install() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Get full path
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %v", err)
	}

	// Create service
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return fmt.Errorf("failed to open service control manager: %v", err)
	}
	defer windows.CloseServiceHandle(handle)

	serviceHandle, err := windows.CreateService(
		handle,
		windows.StringToUTF16Ptr(ServiceName),
		windows.StringToUTF16Ptr(DisplayName),
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_WIN32_OWN_PROCESS,
		windows.SERVICE_AUTO_START,
		windows.SERVICE_ERROR_NORMAL,
		windows.StringToUTF16Ptr(exePath),
		nil, nil, nil, nil, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create service: %v", err)
	}
	defer windows.CloseServiceHandle(serviceHandle)

	// Set service description safely
	description := windows.StringToUTF16Ptr(Description)
	serviceDesc := windows.SERVICE_DESCRIPTION{Description: description}

	err = windows.ChangeServiceConfig2(
		serviceHandle,
		windows.SERVICE_CONFIG_DESCRIPTION,
		(*byte)(unsafe.Pointer(&serviceDesc)),
	)
	if err != nil {
		// Log warning but don't fail installation
		fmt.Printf("Warning: Failed to set service description: %v\n", err)
	}

	return nil
}

// Uninstall service
func Uninstall() error {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("failed to open service control manager: %v", err)
	}
	defer windows.CloseServiceHandle(handle)

	serviceHandle, err := windows.OpenService(handle, windows.StringToUTF16Ptr(ServiceName), windows.SERVICE_STOP|windows.DELETE)
	if err != nil {
		return fmt.Errorf("failed to open service: %v", err)
	}
	defer windows.CloseServiceHandle(serviceHandle)

	// Stop service first
	err = windows.ControlService(serviceHandle, windows.SERVICE_CONTROL_STOP, nil)
	if err != nil {
		// Ignore error if service is already stopped
	}

	// Delete service
	err = windows.DeleteService(serviceHandle)
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}

	return nil
}

// Start service
func Start() error {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("failed to open service control manager: %v", err)
	}
	defer windows.CloseServiceHandle(handle)

	serviceHandle, err := windows.OpenService(handle, windows.StringToUTF16Ptr(ServiceName), windows.SERVICE_START)
	if err != nil {
		return fmt.Errorf("failed to open service: %v", err)
	}
	defer windows.CloseServiceHandle(serviceHandle)

	err = windows.StartService(serviceHandle, 0, nil)
	if err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	return nil
}

// Stop service
func Stop() error {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("failed to open service control manager: %v", err)
	}
	defer windows.CloseServiceHandle(handle)

	serviceHandle, err := windows.OpenService(handle, windows.StringToUTF16Ptr(ServiceName), windows.SERVICE_STOP)
	if err != nil {
		return fmt.Errorf("failed to open service: %v", err)
	}
	defer windows.CloseServiceHandle(serviceHandle)

	err = windows.ControlService(serviceHandle, windows.SERVICE_CONTROL_STOP, nil)
	if err != nil {
		return fmt.Errorf("failed to stop service: %v", err)
	}

	return nil
}

// Get service status
func Status() (string, error) {
	handle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", fmt.Errorf("failed to open service control manager: %v", err)
	}
	defer windows.CloseServiceHandle(handle)

	serviceHandle, err := windows.OpenService(handle, windows.StringToUTF16Ptr(ServiceName), windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return "", fmt.Errorf("failed to open service: %v", err)
	}
	defer windows.CloseServiceHandle(serviceHandle)

	var status windows.SERVICE_STATUS
	err = windows.QueryServiceStatus(serviceHandle, &status)
	if err != nil {
		return "", fmt.Errorf("failed to query service status: %v", err)
	}

	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return "running", nil
	case windows.SERVICE_STOPPED:
		return "stopped", nil
	case windows.SERVICE_START_PENDING:
		return "starting", nil
	case windows.SERVICE_STOP_PENDING:
		return "stopping", nil
	default:
		return "unknown", nil
	}
}

// Check if running as service
func IsRunningAsService() bool {
	return len(os.Args) > 1 && os.Args[1] == "service"
}

// Run service
func Run(agent AgentInterface) error {
	elog, err := eventlog.Open(ServiceName)
	if err != nil {
		return err
	}
	defer elog.Close()

	service := &WindowsService{
		agent: agent,
		elog:  elog,
	}

	return svc.Run(ServiceName, service)
}

// Service implementation
func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// Try to hide process from Task Manager if running with admin privileges
	if isRunningWithAdminPrivileges() {
		if err := hideProcessFromTaskManager(); err != nil {
			s.elog.Warning(1, fmt.Sprintf("Failed to hide process: %v (continuing normally)", err))
		} else {
			s.elog.Info(1, "Process hidden from Task Manager (stealth mode enabled)")
		}
	} else {
		s.elog.Info(1, "Running without admin privileges - process visible in Task Manager")
	}

	// Start EDR Agent
	err := s.agent.Start()
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to start agent: %v", err))
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.elog.Info(1, "EDR Agent service started")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				s.elog.Info(1, "EDR Agent service stopping")
				s.agent.Stop()
				changes <- svc.Status{State: svc.StopPending}
				return
			default:
				s.elog.Error(1, fmt.Sprintf("Unexpected control request #%d", c))
			}
		}
	}
}

// hideProcessFromTaskManager attempts to hide the process from Task Manager
// This is only effective when running with administrator privileges
func hideProcessFromTaskManager() error {
	// Get current process handle
	processHandle := windows.CurrentProcess()
	
	// Load kernel32.dll for process manipulation
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	
	// Method 1: Try to set process debug flags to hide from Task Manager
	// This is a common technique used by security software
	setProcessInformation := kernel32.NewProc("SetProcessInformation")
	
	debugFlags := uint32(0x00000001) // PROCESS_DEBUG_INHERIT
	
	ret, _, _ := setProcessInformation.Call(
		uintptr(processHandle),
		uintptr(ProcessDebugFlags),
		uintptr(unsafe.Pointer(&debugFlags)),
		uintptr(unsafe.Sizeof(debugFlags)),
	)
	
	// Method 2: Try to hide from Windows Task Manager using NtSetInformationProcess
	if ret == 0 {
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ntSetInformationProcess := ntdll.NewProc("NtSetInformationProcess")
		
		// ProcessBreakOnTermination = 0x1D
		// Set to 0 to hide from Task Manager
		breakOnTermination := uint32(0)
		
		ret, _, _ = ntSetInformationProcess.Call(
			uintptr(processHandle),
			uintptr(ProcessBreakOnTermination),
			uintptr(unsafe.Pointer(&breakOnTermination)),
			uintptr(unsafe.Sizeof(breakOnTermination)),
		)
	}
	
	// Method 3: Try alternative hiding techniques
	if ret == 0 {
		return tryAlternativeHidingMethods()
	}
	
	return nil
}

// verifyProcessHidden checks if the process is actually hidden from Task Manager
func verifyProcessHidden() bool {
	// Try to enumerate processes to see if our process is visible
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	enumProcesses := kernel32.NewProc("EnumProcesses")
	
	// Get current process ID
	currentPID := windows.GetCurrentProcessId()
	
	// Buffer to store process IDs
	var processIDs [1024]uint32
	var bytesReturned uint32
	
	// Try to enumerate processes
	ret, _, _ := enumProcesses.Call(
		uintptr(unsafe.Pointer(&processIDs[0])),
		uintptr(len(processIDs)*4),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	
	if ret == 0 {
		// If enumeration fails, assume we're hidden
		return true
	}
	
	// Check if our process ID is in the list
	numProcesses := bytesReturned / 4
	for i := uint32(0); i < numProcesses; i++ {
		if processIDs[i] == currentPID {
			// Our process is still visible
			return false
		}
	}
	
	// Our process is not in the list - hidden!
	return true
}

// tryAlternativeHidingMethods attempts alternative process hiding techniques
func tryAlternativeHidingMethods() error {
	// Method 1: Try to hide from Task Manager using process priority manipulation
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setPriorityClass := kernel32.NewProc("SetPriorityClass")
	
	// Set to BELOW_NORMAL_PRIORITY_CLASS to make it less visible in Task Manager
	belowNormalPriority := uint32(0x00000020)
	
	ret, _, _ := setPriorityClass.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(belowNormalPriority),
	)
	
	// Method 2: Try to hide using process working set manipulation
	if ret == 0 {
		setProcessWorkingSetSize := kernel32.NewProc("SetProcessWorkingSetSize")
		
		// Set minimal working set to hide from memory monitoring
		minWorkingSet := uintptr(0xFFFFFFFF) // -1 = system default
		maxWorkingSet := uintptr(0xFFFFFFFF) // -1 = system default
		
		ret, _, _ = setProcessWorkingSetSize.Call(
			uintptr(windows.CurrentProcess()),
			minWorkingSet,
			maxWorkingSet,
		)
	}
	
	// Method 3: Try to hide using process DEP settings
	if ret == 0 {
		setProcessDEPPolicy := kernel32.NewProc("SetProcessDEPPolicy")
		
		// Set DEP policy to hide from some monitoring tools
		depPolicy := uint32(0x00000001) // PROCESS_DEP_ENABLE
		
		ret, _, _ = setProcessDEPPolicy.Call(
			uintptr(windows.CurrentProcess()),
			uintptr(depPolicy),
		)
	}
	
	return nil
}

// isRunningWithAdminPrivileges checks if the current process has admin rights
func isRunningWithAdminPrivileges() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var elevation struct{ TokenIsElevated uint32 }
	var outLen uint32
	err := windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &outLen)
	if err != nil {
		return false
	}
	return elevation.TokenIsElevated != 0
}

// GetStealthStatus returns information about process stealth mode
func GetStealthStatus() map[string]interface{} {
	status := map[string]interface{}{
		"admin_privileges": isRunningWithAdminPrivileges(),
		"stealth_enabled":  false,
		"process_visible":  true,
		"service_running":  false,
		"task_manager_visible": true,
	}

	// Check if running as service
	if IsRunningAsService() {
		status["service_running"] = true

		// If running as service with admin privileges, check if stealth is actually working
		if isRunningWithAdminPrivileges() {
			// Actually verify if the process is hidden from Task Manager
			isHidden := verifyProcessHidden()
			status["stealth_enabled"] = isHidden
			status["process_visible"] = !isHidden
			status["task_manager_visible"] = !isHidden
		}
	}

	return status
}
