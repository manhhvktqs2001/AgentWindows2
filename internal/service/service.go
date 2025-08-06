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

	// Set service description
	description := windows.StringToUTF16Ptr(Description)
	windows.ChangeServiceConfig2(serviceHandle, windows.SERVICE_CONFIG_DESCRIPTION, (*byte)(unsafe.Pointer(&windows.SERVICE_DESCRIPTION{Description: description})))

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