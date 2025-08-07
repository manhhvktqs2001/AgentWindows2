package response

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// ActionEngine thực hiện các hành động tự động
type ActionEngine struct {
	config *config.ResponseConfig
	logger *utils.Logger

	// Action components
	quarantineManager *QuarantineManager
	processController *WindowsProcessController
	networkController *WindowsNetworkController

	// State
	quarantinedFiles    map[string]bool
	terminatedProcesses map[int]bool
	blockedConnections  map[string]bool
}

// NewActionEngine tạo Action Engine mới
func NewActionEngine(cfg *config.ResponseConfig, logger *utils.Logger) *ActionEngine {
	ae := &ActionEngine{
		config:              cfg,
		logger:              logger,
		quarantinedFiles:    make(map[string]bool),
		terminatedProcesses: make(map[int]bool),
		blockedConnections:  make(map[string]bool),
	}

	// Initialize action components
	ae.quarantineManager = NewQuarantineManager(cfg, logger)
	ae.processController = NewWindowsProcessController(cfg, logger)
	ae.networkController = NewWindowsNetworkController(cfg, logger)

	return ae
}

// QuarantineFile cách ly file
func (ae *ActionEngine) QuarantineFile(filePath string) error {
	ae.logger.Info("Quarantining file: %s", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// Check if already quarantined
	if ae.quarantinedFiles[filePath] {
		ae.logger.Debug("File already quarantined: %s", filePath)
		return nil
	}

	// Perform quarantine
	err := ae.quarantineManager.QuarantineFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to quarantine file: %w", err)
	}

	// Update state
	ae.quarantinedFiles[filePath] = true
	ae.logger.Info("File quarantined successfully: %s", filePath)

	return nil
}

// RestoreFile khôi phục file từ quarantine
func (ae *ActionEngine) RestoreFile(filePath string) error {
	ae.logger.Info("Restoring file: %s", filePath)

	// Check if file was quarantined
	if !ae.quarantinedFiles[filePath] {
		return fmt.Errorf("file was not quarantined: %s", filePath)
	}

	// Perform restore
	err := ae.quarantineManager.RestoreFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	// Update state
	delete(ae.quarantinedFiles, filePath)
	ae.logger.Info("File restored successfully: %s", filePath)

	return nil
}

// TerminateProcesses kết thúc processes
func (ae *ActionEngine) TerminateProcesses(processID int) error {
	ae.logger.Info("Terminating process: %d", processID)

	// Check if process was already terminated
	if ae.terminatedProcesses[processID] {
		ae.logger.Debug("Process already terminated: %d", processID)
		return nil
	}

	// Perform process termination
	err := ae.processController.TerminateProcesses(processID)
	if err != nil {
		return fmt.Errorf("failed to terminate process: %w", err)
	}

	// Update state
	ae.terminatedProcesses[processID] = true
	ae.logger.Info("Process terminated successfully: %d", processID)

	return nil
}

// BlockNetworkConnections chặn kết nối mạng
func (ae *ActionEngine) BlockNetworkConnections(processID int) error {
	ae.logger.Info("Blocking network connections for process: %d", processID)

	// Create connection key
	connectionKey := fmt.Sprintf("process_%d", processID)

	// Check if already blocked
	if ae.blockedConnections[connectionKey] {
		ae.logger.Debug("Network connections already blocked for process: %d", processID)
		return nil
	}

	// Perform network blocking
	err := ae.networkController.BlockNetworkConnections(processID)
	if err != nil {
		return fmt.Errorf("failed to block network connections: %w", err)
	}

	// Update state
	ae.blockedConnections[connectionKey] = true
	ae.logger.Info("Network connections blocked successfully for process: %d", processID)

	return nil
}

// UnblockNetworkConnections bỏ chặn kết nối mạng
func (ae *ActionEngine) UnblockNetworkConnections(processID int) error {
	ae.logger.Info("Unblocking network connections for process: %d", processID)

	// Create connection key
	connectionKey := fmt.Sprintf("process_%d", processID)

	// Check if was blocked
	if !ae.blockedConnections[connectionKey] {
		return fmt.Errorf("network connections were not blocked for process: %d", processID)
	}

	// Perform network unblocking
	err := ae.networkController.UnblockConnection("", "", "") // Simplified for now
	if err != nil {
		return fmt.Errorf("failed to unblock network connections: %w", err)
	}

	// Update state
	delete(ae.blockedConnections, connectionKey)
	ae.logger.Info("Network connections unblocked successfully for process: %d", processID)

	return nil
}

// GetQuarantineList trả về danh sách file đã quarantine
func (ae *ActionEngine) GetQuarantineList() []string {
	var files []string
	for filePath := range ae.quarantinedFiles {
		files = append(files, filePath)
	}
	return files
}

// GetTerminatedProcesses trả về danh sách process đã terminate
func (ae *ActionEngine) GetTerminatedProcesses() []int {
	var processes []int
	for processID := range ae.terminatedProcesses {
		processes = append(processes, processID)
	}
	return processes
}

// GetBlockedConnections trả về danh sách kết nối đã block
func (ae *ActionEngine) GetBlockedConnections() []string {
	var connections []string
	for connectionKey := range ae.blockedConnections {
		connections = append(connections, connectionKey)
	}
	return connections
}

// Start khởi động Action Engine
func (ae *ActionEngine) Start() error {
	ae.logger.Info("Starting Action Engine...")

	// Start action components
	if err := ae.quarantineManager.Start(); err != nil {
		return fmt.Errorf("failed to start quarantine manager: %w", err)
	}

	if err := ae.processController.Start(); err != nil {
		return fmt.Errorf("failed to start process controller: %w", err)
	}

	if err := ae.networkController.Start(); err != nil {
		return fmt.Errorf("failed to start network controller: %w", err)
	}

	ae.logger.Info("Action Engine started successfully")
	return nil
}

// Stop dừng Action Engine
func (ae *ActionEngine) Stop() {
	ae.logger.Info("Stopping Action Engine...")

	ae.quarantineManager.Stop()
	ae.processController.Stop()
	ae.networkController.Stop()

	ae.logger.Info("Action Engine stopped")
}

// GetActionStats trả về thống kê hành động
func (ae *ActionEngine) GetActionStats() map[string]interface{} {
	return map[string]interface{}{
		"quarantined_files_count":    len(ae.quarantinedFiles),
		"terminated_processes_count": len(ae.terminatedProcesses),
		"blocked_connections_count":  len(ae.blockedConnections),
		"auto_quarantine_enabled":    true, // Default value
		"block_execution_enabled":    true, // Default value
	}
}

// QuarantineManager quản lý quarantine files
type QuarantineManager struct {
	config        *config.ResponseConfig
	logger        *utils.Logger
	quarantineDir string
}

// NewQuarantineManager tạo Quarantine Manager mới
func NewQuarantineManager(cfg *config.ResponseConfig, logger *utils.Logger) *QuarantineManager {
	return &QuarantineManager{
		config:        cfg,
		logger:        logger,
		quarantineDir: "quarantine",
	}
}

// Start khởi động Quarantine Manager
func (qm *QuarantineManager) Start() error {
	// Create quarantine directory if not exists
	if err := os.MkdirAll(qm.quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	qm.logger.Info("Quarantine Manager started")
	return nil
}

// Stop dừng Quarantine Manager
func (qm *QuarantineManager) Stop() {
	qm.logger.Info("Quarantine Manager stopped")
}

// QuarantineFile cách ly file
func (qm *QuarantineManager) QuarantineFile(filePath string) error {
	// Create quarantine file path
	fileName := filepath.Base(filePath)
	quarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_%d", fileName, time.Now().Unix()))

	// Move file to quarantine
	if err := os.Rename(filePath, quarantinePath); err != nil {
		return fmt.Errorf("failed to move file to quarantine: %w", err)
	}

	qm.logger.Info("File quarantined: %s -> %s", filePath, quarantinePath)
	return nil
}

// RestoreFile khôi phục file từ quarantine
func (qm *QuarantineManager) RestoreFile(filePath string) error {
	// This is a simplified implementation
	// In a real system, you would need to track the original location
	qm.logger.Info("File restore requested: %s", filePath)
	return fmt.Errorf("file restore not implemented yet")
}

// ProcessController quản lý processes
type ProcessController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewProcessController tạo Process Controller mới
func NewProcessController(cfg *config.ResponseConfig, logger *utils.Logger) *ProcessController {
	return &ProcessController{
		config: cfg,
		logger: logger,
	}
}

// Start khởi động Process Controller
func (pc *ProcessController) Start() error {
	pc.logger.Info("Process Controller started")
	return nil
}

// Stop dừng Process Controller
func (pc *ProcessController) Stop() {
	pc.logger.Info("Process Controller stopped")
}

// TerminateProcess kết thúc process
func (pc *ProcessController) TerminateProcess(processID int) error {
	// This is a simplified implementation
	// In a real system, you would use Windows API to terminate the process
	pc.logger.Info("Process termination requested: %d", processID)
	return fmt.Errorf("process termination not implemented yet")
}

// NetworkController quản lý network connections
type NetworkController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewNetworkController tạo Network Controller mới
func NewNetworkController(cfg *config.ResponseConfig, logger *utils.Logger) *NetworkController {
	return &NetworkController{
		config: cfg,
		logger: logger,
	}
}

// Start khởi động Network Controller
func (nc *NetworkController) Start() error {
	nc.logger.Info("Network Controller started")
	return nil
}

// Stop dừng Network Controller
func (nc *NetworkController) Stop() {
	nc.logger.Info("Network Controller stopped")
}

// BlockProcessConnections chặn kết nối mạng của process
func (nc *NetworkController) BlockProcessConnections(processID int) error {
	// This is a simplified implementation
	// In a real system, you would use Windows Firewall API
	nc.logger.Info("Network blocking requested for process: %d", processID)
	return fmt.Errorf("network blocking not implemented yet")
}

// UnblockProcessConnections bỏ chặn kết nối mạng của process
func (nc *NetworkController) UnblockProcessConnections(processID int) error {
	// This is a simplified implementation
	// In a real system, you would use Windows Firewall API
	nc.logger.Info("Network unblocking requested for process: %d", processID)
	return fmt.Errorf("network unblocking not implemented yet")
}
