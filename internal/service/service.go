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

	fmt.Println("✅ Service installed - will be VISIBLE in Task Manager when running")
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

// Service implementation - ALWAYS VISIBLE VERSION
func (s *WindowsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	// ENSURE PROCESS IS ALWAYS VISIBLE IN TASK MANAGER
	s.elog.Info(1, "EDR Agent Service starting - VISIBLE MODE")
	s.elog.Info(1, "Process will be VISIBLE in Task Manager as 'edr-agent.exe'")

	// Make sure process is visible by setting normal priority
	ensureProcessVisibility()

	// Start EDR Agent
	err := s.agent.Start()
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to start agent: %v", err))
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.elog.Info(1, "EDR Agent service started successfully")
	s.elog.Info(1, "Process is VISIBLE in Task Manager - stealth mode DISABLED")

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

// ensureProcessVisibility makes sure the process is visible in Task Manager
func ensureProcessVisibility() {
	// Set normal process priority to ensure visibility
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	setPriorityClass := kernel32.NewProc("SetPriorityClass")

	// Use NORMAL_PRIORITY_CLASS to ensure visibility
	normalPriority := uint32(0x00000020) // NORMAL_PRIORITY_CLASS

	ret, _, _ := setPriorityClass.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(normalPriority),
	)

	if ret != 0 {
		// Successfully set normal priority
	}

	// Make sure we don't use any hiding techniques
	// DO NOT call any process hiding functions
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

// GetStealthStatus returns information about process visibility (always visible now)
func GetStealthStatus() map[string]interface{} {
	status := map[string]interface{}{
		"admin_privileges":     isRunningWithAdminPrivileges(),
		"stealth_enabled":      false, // ALWAYS FALSE - stealth disabled
		"process_visible":      true,  // ALWAYS TRUE - always visible
		"service_running":      false,
		"task_manager_visible": true, // ALWAYS TRUE - always visible in Task Manager
		"visibility_mode":      "ALWAYS_VISIBLE",
		"description":          "Process is ALWAYS visible in Task Manager",
	}

	// Check if running as service
	if IsRunningAsService() {
		status["service_running"] = true
		status["description"] = "Service is ALWAYS visible in Task Manager as 'edr-agent.exe'"
	}

	return status
}

// GetVisibilityInfo returns detailed visibility information
func GetVisibilityInfo() map[string]interface{} {
	return map[string]interface{}{
		"stealth_mode":         false,
		"always_visible":       true,
		"task_manager_visible": true,
		"process_name":         "edr-agent.exe",
		"process_description":  "EDR Security Agent",
		"hiding_disabled":      true,
		"normal_priority":      true,
		"admin_required":       true,
		"visibility_features": []string{
			"Normal process priority",
			"Standard Windows service",
			"Visible in Task Manager",
			"No process hiding",
			"Standard process name",
		},
	}
}
