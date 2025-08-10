package response

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-agent-windows/internal/communication"
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// ActionEngine thực hiện các hành động tự động
type ActionEngine struct {
	config *config.ResponseConfig
	logger *utils.Logger

	// Server communication
	serverClient *communication.ServerClient

	// Action components
	quarantineManager *QuarantineManager
	processController *WindowsProcessController
	networkController *WindowsNetworkController

	// State
	quarantinedFiles    map[string]bool
	terminatedProcesses map[int]bool
	blockedConnections  map[string]bool
	mu                  sync.RWMutex
}

// NewActionEngine tạo Action Engine mới
func NewActionEngine(cfg *config.ResponseConfig, logger *utils.Logger, serverClient *communication.ServerClient) *ActionEngine {
	ae := &ActionEngine{
		config:              cfg,
		logger:              logger,
		serverClient:        serverClient,
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

// QuarantineFile cách ly file với improved error handling
func (ae *ActionEngine) QuarantineFile(filePath string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.logger.Info("Quarantining file: %s", filePath)

	// Validate input
	if filePath == "" {
		ae.logger.Warn("Empty file path provided for quarantine")
		return nil
	}

	// Normalize path
	normalizedPath := filepath.Clean(filePath)

	// Check if file exists
	if _, err := os.Stat(normalizedPath); os.IsNotExist(err) {
		ae.logger.Warn("File does not exist, skipping quarantine: %s", normalizedPath)
		return nil
	}

	// Check if already quarantined
	if ae.quarantinedFiles[normalizedPath] {
		ae.logger.Debug("File already quarantined: %s", normalizedPath)
		return nil
	}

	// Skip protected system files
	if ae.quarantineManager.isProtectedSystemPath(normalizedPath) {
		ae.logger.Warn("Skipping quarantine for protected system file: %s", normalizedPath)
		return nil
	}

	// Perform quarantine
	quarantinePath, err := ae.quarantineManager.QuarantineFile(normalizedPath)
	if err != nil {
		ae.logger.Error("Failed to quarantine file locally: %v", err)
		return fmt.Errorf("failed to quarantine file: %w", err)
	}

	// Mark as quarantined
	ae.quarantinedFiles[normalizedPath] = true
	ae.logger.Info("File quarantined locally successfully: %s", normalizedPath)

	// Upload to server (async)
	go func() {
		if ae.serverClient != nil && quarantinePath != "" {
			agentID := ae.serverClient.GetAgentID()
			if agentID != "" {
				if err := ae.serverClient.UploadQuarantineFile(agentID, quarantinePath); err != nil {
					ae.logger.Error("Failed to upload file to server: %v", err)
				} else {
					ae.logger.Info("✅ File uploaded to server successfully: %s", filepath.Base(quarantinePath))
					// Clean up local file after successful upload
					if err := os.Remove(quarantinePath); err != nil {
						ae.logger.Debug("Failed to remove local quarantine file: %v", err)
					} else {
						ae.logger.Info("🧹 Deleted local quarantine file after upload: %s", quarantinePath)
					}
				}
			}
		}
	}()

	return nil
}

// RestoreFile phục hồi file từ quarantine
func (ae *ActionEngine) RestoreFile(filePath string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.logger.Info("Restoring file: %s", filePath)

	if !ae.quarantinedFiles[filePath] {
		return fmt.Errorf("file was not quarantined: %s", filePath)
	}

	err := ae.quarantineManager.RestoreFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to restore file: %w", err)
	}

	delete(ae.quarantinedFiles, filePath)
	ae.logger.Info("File restored successfully: %s", filePath)
	return nil
}

// TerminateProcesses chấm dứt process
func (ae *ActionEngine) TerminateProcesses(processID int) error {
	if processID <= 0 {
		ae.logger.Debug("Skip terminate: invalid PID %d", processID)
		return nil
	}

	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.logger.Info("Terminating process: %d", processID)

	if ae.terminatedProcesses[processID] {
		ae.logger.Debug("Process already terminated: %d", processID)
		return nil
	}

	err := ae.processController.TerminateProcesses(processID)
	if err != nil {
		return fmt.Errorf("failed to terminate process: %w", err)
	}

	ae.terminatedProcesses[processID] = true
	ae.logger.Info("Process terminated successfully: %d", processID)
	return nil
}

// BlockNetworkConnections chặn kết nối mạng
func (ae *ActionEngine) BlockNetworkConnections(processID int) error {
	if processID <= 0 {
		ae.logger.Debug("Skip block network: invalid PID %d", processID)
		return nil
	}

	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.logger.Info("Blocking network connections for process: %d", processID)

	connectionKey := fmt.Sprintf("process_%d", processID)

	if ae.blockedConnections[connectionKey] {
		ae.logger.Debug("Network connections already blocked for process: %d", processID)
		return nil
	}

	err := ae.networkController.BlockNetworkConnections(processID)
	if err != nil {
		return fmt.Errorf("failed to block network connections: %w", err)
	}

	ae.blockedConnections[connectionKey] = true
	ae.logger.Info("Network connections blocked successfully for process: %d", processID)
	return nil
}

// Start khởi động Action Engine
func (ae *ActionEngine) Start() error {
	ae.logger.Info("Starting Action Engine...")

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

// QuarantineManager quản lý việc cách ly file
type QuarantineManager struct {
	config        *config.ResponseConfig
	logger        *utils.Logger
	quarantineDir string
	mu            sync.RWMutex
}

func NewQuarantineManager(cfg *config.ResponseConfig, logger *utils.Logger) *QuarantineManager {
	quarantineDir, err := filepath.Abs("quarantine")
	if err != nil {
		quarantineDir = "quarantine"
	}

	return &QuarantineManager{
		config:        cfg,
		logger:        logger,
		quarantineDir: quarantineDir,
	}
}

func (qm *QuarantineManager) Start() error {
	if err := os.MkdirAll(qm.quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	qm.logger.Info("Quarantine Manager started")
	return nil
}

func (qm *QuarantineManager) Stop() {
	qm.logger.Info("Quarantine Manager stopped")
}

// QuarantineFile thực hiện cách ly file
func (qm *QuarantineManager) QuarantineFile(filePath string) (string, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Skip self-quarantine
	if strings.Contains(strings.ToLower(filePath), strings.ToLower(qm.quarantineDir)) {
		qm.logger.Debug("Skipping self-quarantine path: %s", filePath)
		return "", nil
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		qm.logger.Warn("File does not exist, skipping quarantine: %s", filePath)
		return "", nil
	}

	// Skip protected paths
	if qm.isProtectedSystemPath(filePath) {
		qm.logger.Warn("Protected system path detected, skipping quarantine: %s", filePath)
		return "", nil
	}

	// Create quarantine file path
	fileName := filepath.Base(filePath)
	quarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_%d", fileName, time.Now().Unix()))

	// Try to move file first (most efficient)
	if err := os.Rename(filePath, quarantinePath); err == nil {
		if qm.verifyQuarantinedFile(quarantinePath) {
			qm.logger.Info("File quarantined (moved): %s -> %s", filePath, quarantinePath)
			return quarantinePath, nil
		} else {
			// Move succeeded but file is empty, restore and try copy
			qm.logger.Warn("Moved file is empty, restoring and trying copy method")
			if restoreErr := os.Rename(quarantinePath, filePath); restoreErr != nil {
				qm.logger.Error("Failed to restore file after empty move: %v", restoreErr)
			}
		}
	}

	// Try to copy file
	if err := qm.copyFile(filePath, quarantinePath); err == nil {
		qm.logger.Info("File quarantined (copied): %s -> %s", filePath, quarantinePath)
		return quarantinePath, nil
	}

	// Handle directories
	if stat, err := os.Stat(filePath); err == nil && stat.IsDir() {
		if err := qm.quarantineDirectory(filePath); err == nil {
			qm.logger.Info("Directory quarantined (contents copied): %s", filePath)
			return "", nil
		}
	}

	return "", fmt.Errorf("failed to quarantine file: %s", filePath)
}

// copyFile sao chép file
func (qm *QuarantineManager) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// verifyQuarantinedFile kiểm tra file đã được quarantine
func (qm *QuarantineManager) verifyQuarantinedFile(quarantinePath string) bool {
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		qm.logger.Warn("Quarantined file does not exist: %s", quarantinePath)
		return false
	}

	if fileInfo, err := os.Stat(quarantinePath); err == nil {
		if fileInfo.Size() == 0 {
			qm.logger.Warn("Quarantined file is empty: %s", quarantinePath)
			return false
		}
		return true
	}

	return false
}

// quarantineDirectory cách ly thư mục
func (qm *QuarantineManager) quarantineDirectory(dirPath string) error {
	dirName := filepath.Base(dirPath)
	quarantineDir := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_contents_%d", dirName, time.Now().Unix()))

	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	successCount := 0
	totalCount := 0

	walkErrTotal := filepath.Walk(dirPath, func(src string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}

		totalCount++

		if src == dirPath {
			return nil
		}

		rel, err := filepath.Rel(dirPath, src)
		if err != nil {
			return nil
		}

		dst := filepath.Join(quarantineDir, rel)

		if info.IsDir() {
			if err := os.MkdirAll(dst, 0755); err != nil {
				qm.logger.Debug("Failed to create destination directory: %s", dst)
			}
			return nil
		}

		if err := qm.copyFile(src, dst); err != nil {
			qm.logger.Debug("Failed to quarantine file: %s -> %s: %v", src, dst, err)
			return nil
		}

		successCount++
		return nil
	})

	if walkErrTotal != nil {
		qm.logger.Debug("Directory walk encountered errors: %v", walkErrTotal)
	}
	qm.logger.Info("Directory quarantine completed: %d/%d files successfully quarantined from %s", successCount, totalCount, dirPath)

	if successCount == 0 {
		if err := os.RemoveAll(quarantineDir); err != nil {
			qm.logger.Debug("Failed to remove empty quarantine directory: %v", err)
		}
		return fmt.Errorf("no files could be quarantined from directory: %s", dirPath)
	}

	return nil
}

// isProtectedSystemPath kiểm tra đường dẫn hệ thống được bảo vệ
func (qm *QuarantineManager) isProtectedSystemPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	protectedPrefixes := []string{
		`c:\windows\system32\config\`,
		`c:\windows\system32\drivers\`,
		`c:\windows\winsxs\`,
		`c:\windows\syswow64\`,
		`c:\windows\servicing\`,
		`c:\windows\security\`,
		`c:\windows\boot\`,
		`c:\windows\system32\sru\`,
		`c:\$recycle.bin\`,
	}

	protectedFiles := []string{
		`c:\windows\system32\ntoskrnl.exe`,
		`c:\windows\system32\winlogon.exe`,
		`c:\windows\system32\lsass.exe`,
		`c:\windows\system32\csrss.exe`,
		`c:\windows\system32\wininit.exe`,
		`c:\windows\system32\services.exe`,
		`c:\hiberfil.sys`,
		`c:\pagefile.sys`,
		`c:\swapfile.sys`,
	}

	for _, p := range protectedPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}

	for _, f := range protectedFiles {
		if lower == f {
			return true
		}
	}

	return false
}

// RestoreFile phục hồi file từ quarantine
func (qm *QuarantineManager) RestoreFile(filePath string) error {
	qm.logger.Info("File restore requested: %s", filePath)
	return fmt.Errorf("file restore not implemented yet")
}

// ProcessController và NetworkController giữ nguyên như cũ
type ProcessController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

func NewProcessController(cfg *config.ResponseConfig, logger *utils.Logger) *ProcessController {
	return &ProcessController{
		config: cfg,
		logger: logger,
	}
}

func (pc *ProcessController) Start() error {
	pc.logger.Info("Process Controller started")
	return nil
}

func (pc *ProcessController) Stop() {
	pc.logger.Info("Process Controller stopped")
}

func (pc *ProcessController) TerminateProcess(processID int) error {
	pc.logger.Info("Process termination requested: %d", processID)
	return fmt.Errorf("process termination not implemented yet")
}

type NetworkController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

func NewNetworkController(cfg *config.ResponseConfig, logger *utils.Logger) *NetworkController {
	return &NetworkController{
		config: cfg,
		logger: logger,
	}
}

func (nc *NetworkController) Start() error {
	nc.logger.Info("Network Controller started")
	return nil
}

func (nc *NetworkController) Stop() {
	nc.logger.Info("Network Controller stopped")
}

func (nc *NetworkController) BlockProcessConnections(processID int) error {
	nc.logger.Info("Network blocking requested for process: %d", processID)
	return fmt.Errorf("network blocking not implemented yet")
}

func (nc *NetworkController) UnblockProcessConnections(processID int) error {
	nc.logger.Info("Network unblocking requested for process: %d", processID)
	return fmt.Errorf("network unblocking not implemented yet")
}
