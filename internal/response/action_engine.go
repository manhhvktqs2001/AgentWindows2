// internal/response/action_engine.go
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

type ActionEngine struct {
	config *config.ResponseConfig
	logger *utils.Logger

	serverClient *communication.ServerClient

	quarantineManager *QuarantineManager
	processController *WindowsProcessController
	networkController *WindowsNetworkController

	// Enhanced state tracking
	quarantinedFiles    map[string]bool
	terminatedProcesses map[int]bool
	blockedConnections  map[string]bool
	failedOperations    map[string]int
	mu                  sync.RWMutex
}

func NewActionEngine(cfg *config.ResponseConfig, logger *utils.Logger, serverClient *communication.ServerClient) *ActionEngine {
	ae := &ActionEngine{
		config:              cfg,
		logger:              logger,
		serverClient:        serverClient,
		quarantinedFiles:    make(map[string]bool),
		terminatedProcesses: make(map[int]bool),
		blockedConnections:  make(map[string]bool),
		failedOperations:    make(map[string]int),
	}

	ae.quarantineManager = NewQuarantineManager(cfg, logger)
	ae.processController = NewWindowsProcessController(cfg, logger)
	ae.networkController = NewWindowsNetworkController(cfg, logger)

	return ae
}

func (ae *ActionEngine) QuarantineFile(filePath string) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	// Enhanced validation
	if filePath == "" {
		ae.logger.Debug("Empty file path provided for quarantine")
		return nil
	}

	normalizedPath := filepath.Clean(filePath)

	// Check if file exists and is accessible
	fileInfo, err := os.Stat(normalizedPath)
	if os.IsNotExist(err) {
		ae.logger.Debug("File does not exist, skipping quarantine: %s", normalizedPath)
		return nil
	}
	if err != nil {
		ae.logger.Warn("Cannot access file for quarantine: %s - %v", normalizedPath, err)
		return nil
	}

	// Enhanced system file protection
	if ae.quarantineManager.isProtectedSystemPath(normalizedPath) {
		ae.logger.Warn("Refusing to quarantine protected system file: %s", normalizedPath)
		return nil
	}

	// Skip if already quarantined
	if ae.quarantinedFiles[normalizedPath] {
		ae.logger.Debug("File already quarantined: %s", normalizedPath)
		return nil
	}

	// Check for repeated failures
	if failCount := ae.failedOperations[normalizedPath]; failCount >= 3 {
		ae.logger.Warn("Skipping quarantine due to repeated failures: %s", normalizedPath)
		return nil
	}

	// Skip directories and special files
	if fileInfo.IsDir() {
		ae.logger.Debug("Skipping quarantine of directory: %s", normalizedPath)
		return nil
	}

	// Skip very large files
	if fileInfo.Size() > 500*1024*1024 { // 500MB
		ae.logger.Warn("Skipping quarantine of large file (%d bytes): %s", fileInfo.Size(), normalizedPath)
		return nil
	}

	ae.logger.Info("Quarantining file: %s", normalizedPath)

	// Perform quarantine with enhanced error handling
	quarantinePath, err := ae.quarantineManager.QuarantineFile(normalizedPath)
	if err != nil {
		ae.failedOperations[normalizedPath]++
		ae.logger.Error("Failed to quarantine file: %s - %v", normalizedPath, err)
		return fmt.Errorf("failed to quarantine file: %w", err)
	}

	// Mark as successfully quarantined
	ae.quarantinedFiles[normalizedPath] = true
	delete(ae.failedOperations, normalizedPath) // Clear failure count on success
	ae.logger.Info("File quarantined successfully: %s", normalizedPath)

	// Upload to server asynchronously with better error handling
	if ae.serverClient != nil && quarantinePath != "" {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					ae.logger.Error("Panic during file upload: %v", r)
				}
			}()

			agentID := ae.serverClient.GetAgentID()
			if agentID == "" {
				ae.logger.Debug("Agent ID not set, skipping upload")
				return
			}

			// Upload with retry and timeout
			maxRetries := 3
			for attempt := 1; attempt <= maxRetries; attempt++ {
				if err := ae.serverClient.UploadQuarantineFile(agentID, quarantinePath); err != nil {
					ae.logger.Warn("Upload attempt %d/%d failed: %v", attempt, maxRetries, err)
					if attempt < maxRetries {
						time.Sleep(time.Duration(attempt) * time.Second)
						continue
					}
					ae.logger.Error("Failed to upload file after %d attempts: %v", maxRetries, err)
				} else {
					ae.logger.Info("✅ File uploaded to server successfully: %s", filepath.Base(quarantinePath))
					// Clean up local file after successful upload
					if err := os.Remove(quarantinePath); err != nil {
						ae.logger.Debug("Failed to remove local quarantine file: %v", err)
					} else {
						ae.logger.Info("🧹 Deleted local quarantine file after upload: %s", quarantinePath)
					}
					break
				}
			}
		}()
	}

	return nil
}

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

func (ae *ActionEngine) TerminateProcesses(processID int) error {
	if processID <= 0 || processID == os.Getpid() {
		ae.logger.Debug("Skip terminate: invalid or self PID %d", processID)
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
		ae.logger.Warn("Failed to terminate process %d: %v", processID, err)
		return fmt.Errorf("failed to terminate process: %w", err)
	}

	ae.terminatedProcesses[processID] = true
	ae.logger.Info("Process terminated successfully: %d", processID)
	return nil
}

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
		ae.logger.Warn("Failed to block network connections for process %d: %v", processID, err)
		return fmt.Errorf("failed to block network connections: %w", err)
	}

	ae.blockedConnections[connectionKey] = true
	ae.logger.Info("Network connections blocked successfully for process: %d", processID)
	return nil
}

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

func (ae *ActionEngine) Stop() {
	ae.logger.Info("Stopping Action Engine...")

	ae.quarantineManager.Stop()
	ae.processController.Stop()
	ae.networkController.Stop()

	ae.logger.Info("Action Engine stopped")
}

// Enhanced QuarantineManager
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

func (qm *QuarantineManager) QuarantineFile(filePath string) (string, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Enhanced self-quarantine detection
	if strings.Contains(strings.ToLower(filePath), strings.ToLower(qm.quarantineDir)) {
		qm.logger.Debug("Skipping self-quarantine path: %s", filePath)
		return "", nil
	}

	// Enhanced file existence check
	fileInfo, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		qm.logger.Debug("File does not exist, skipping quarantine: %s", filePath)
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot access file: %w", err)
	}

	// Enhanced protection checks
	if qm.isProtectedSystemPath(filePath) {
		qm.logger.Warn("Protected system path detected, refusing quarantine: %s", filePath)
		return "", fmt.Errorf("cannot quarantine protected system file")
	}

	// Check if file is in use
	if qm.isFileInUse(filePath) {
		qm.logger.Warn("File appears to be in use, skipping quarantine: %s", filePath)
		return "", fmt.Errorf("file is in use")
	}

	// Create unique quarantine file path
	fileName := filepath.Base(filePath)
	timestamp := time.Now().Unix()
	quarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_%d", fileName, timestamp))

	// Try copy first (safer than move for critical files)
	if err := qm.copyFileSecure(filePath, quarantinePath); err != nil {
		qm.logger.Warn("Failed to copy file to quarantine: %v", err)
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	// Verify the copy was successful
	if !qm.verifyQuarantinedFile(quarantinePath, fileInfo.Size()) {
		os.Remove(quarantinePath) // Clean up failed copy
		return "", fmt.Errorf("quarantine copy verification failed")
	}

	qm.logger.Info("File quarantined (copied): %s -> %s", filePath, quarantinePath)
	return quarantinePath, nil
}

func (qm *QuarantineManager) isFileInUse(filePath string) bool {
	// Try to open file exclusively to check if it's in use
	file, err := os.OpenFile(filePath, os.O_RDWR, 0)
	if err != nil {
		// If we can't open it exclusively, it might be in use
		return strings.Contains(strings.ToLower(err.Error()), "being used")
	}
	file.Close()
	return false
}

func (qm *QuarantineManager) copyFileSecure(src, dst string) error {
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

	// Copy with buffer for better performance
	buffer := make([]byte, 64*1024) // 64KB buffer
	_, err = io.CopyBuffer(destFile, sourceFile, buffer)
	if err != nil {
		os.Remove(dst) // Clean up on failure
		return err
	}

	// Ensure data is written to disk
	return destFile.Sync()
}

func (qm *QuarantineManager) verifyQuarantinedFile(quarantinePath string, expectedSize int64) bool {
	fileInfo, err := os.Stat(quarantinePath)
	if err != nil {
		qm.logger.Warn("Quarantined file verification failed - file missing: %s", quarantinePath)
		return false
	}

	if fileInfo.Size() == 0 {
		qm.logger.Warn("Quarantined file verification failed - file empty: %s", quarantinePath)
		return false
	}

	if fileInfo.Size() != expectedSize {
		qm.logger.Warn("Quarantined file verification failed - size mismatch: %s (expected %d, got %d)",
			quarantinePath, expectedSize, fileInfo.Size())
		return false
	}

	return true
}

func (qm *QuarantineManager) isProtectedSystemPath(filePath string) bool {
	lower := strings.ToLower(filePath)

	// Critical Windows system files and directories
	criticalPaths := []string{
		`c:\windows\system32\ntoskrnl.exe`,
		`c:\windows\system32\hal.dll`,
		`c:\windows\system32\kernel32.dll`,
		`c:\windows\system32\ntdll.dll`,
		`c:\windows\system32\user32.dll`,
		`c:\windows\system32\gdi32.dll`,
		`c:\windows\system32\winlogon.exe`,
		`c:\windows\system32\lsass.exe`,
		`c:\windows\system32\csrss.exe`,
		`c:\windows\system32\wininit.exe`,
		`c:\windows\system32\services.exe`,
		`c:\windows\system32\smss.exe`,
		`c:\windows\explorer.exe`,
		`c:\hiberfil.sys`,
		`c:\pagefile.sys`,
		`c:\swapfile.sys`,
	}

	// Protected directories
	protectedDirs := []string{
		`c:\windows\system32\config\`,
		`c:\windows\system32\drivers\`,
		`c:\windows\winsxs\`,
		`c:\windows\boot\`,
		`c:\windows\security\`,
		`c:\windows\servicing\`,
		`c:\windows\system32\sru\`,
		`c:\$recycle.bin\`,
		`c:\recovery\`,
		`c:\system volume information\`,
	}

	// Check critical files
	for _, path := range criticalPaths {
		if lower == path {
			return true
		}
	}

	// Check protected directories
	for _, dir := range protectedDirs {
		if strings.HasPrefix(lower, dir) {
			return true
		}
	}

	// Check if it's our own executable
	if strings.Contains(lower, "edr-agent") {
		return true
	}

	return false
}

func (qm *QuarantineManager) RestoreFile(filePath string) error {
	qm.logger.Info("File restore requested: %s", filePath)
	return fmt.Errorf("file restore not implemented yet")
}

// Legacy ProcessController and NetworkController interfaces for backward compatibility
type ProcessController struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

func NewProcessController(cfg *config.ResponseConfig, logger *utils.Logger) *ProcessController {
	return &ProcessController{config: cfg, logger: logger}
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
	return &NetworkController{config: cfg, logger: logger}
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
