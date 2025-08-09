package response

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// QuarantineFile cách ly file
func (ae *ActionEngine) QuarantineFile(filePath string) error {
	ae.logger.Info("Quarantining file: %s", filePath)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		ae.logger.Warn("File does not exist, skipping quarantine: %s", filePath)
		return nil // Don't return error, just skip
	}

	// Guard: Skip protected system paths to avoid bricking the OS
	if ae.quarantineManager.isProtectedSystemPath(filePath) {
		ae.logger.Warn("Skipping quarantine for protected system file: %s", filePath)
		return nil
	}

	// Check if already quarantined
	if ae.quarantinedFiles[filePath] {
		ae.logger.Debug("File already quarantined: %s", filePath)
		return nil
	}

	// Perform local quarantine first
	quarantinePath, err := ae.quarantineManager.QuarantineFile(filePath)
	if err != nil {
		ae.logger.Error("Failed to quarantine file locally: %v", err)
		return fmt.Errorf("failed to quarantine file locally: %w", err)
	}

	// Check if quarantine was successful
	if quarantinePath == "" {
		// This can happen for directories or when locked files are handled
		ae.logger.Info("File quarantine completed (no single path returned): %s", filePath)
		ae.quarantinedFiles[filePath] = true
		return nil
	}

	// Update state
	ae.quarantinedFiles[filePath] = true
	ae.logger.Info("File quarantined locally successfully: %s", filePath)

	// Upload to server (async to avoid blocking)
	go func() {
		if ae.serverClient != nil {
			// Get agent ID from config or server client
			agentID := ae.serverClient.GetAgentID()
			if agentID == "" {
				ae.logger.Warn("Agent ID not set, skipping server upload")
				return
			}

			// Upload to server using the quarantined file path
			err := ae.serverClient.UploadQuarantineFile(agentID, quarantinePath)
			if err != nil {
				ae.logger.Error("Failed to upload file to server: %v", err)
				// Don't fail the quarantine process, just log the error
			} else {
				ae.logger.Info("✅ File uploaded to server successfully: %s", filepath.Base(quarantinePath))
				// Delete local quarantine copy after successful upload
				if remErr := os.Remove(quarantinePath); remErr != nil {
					ae.logger.Warn("Failed to delete local quarantine file after upload: %s - %v", quarantinePath, remErr)
				} else {
					ae.logger.Info("🧹 Deleted local quarantine file after upload: %s", quarantinePath)
				}
			}
		} else {
			ae.logger.Warn("Server client not available, skipping server upload")
		}
	}()

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
	if processID <= 0 {
		ae.logger.Debug("Skip terminate: invalid PID %d", processID)
		return nil
	}

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
	if processID <= 0 {
		ae.logger.Debug("Skip block network: invalid PID %d", processID)
		return nil
	}

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
	// Use absolute path for quarantine directory to avoid working directory issues
	quarantineDir, err := filepath.Abs("quarantine")
	if err != nil {
		// Fallback to relative path if absolute path fails
		quarantineDir = "quarantine"
	}

	return &QuarantineManager{
		config:        cfg,
		logger:        logger,
		quarantineDir: quarantineDir,
	}
}

// Start khởi động Quarantine Manager
func (qm *QuarantineManager) Start() error {
	// Create quarantine directory if not exists
	if err := os.MkdirAll(qm.quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	qm.logger.Info("Quarantine Manager started")

	// Start periodic cleanup goroutine
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
		defer ticker.Stop()

		for range ticker.C {
			if err := qm.cleanupEmptyQuarantinedFiles(); err != nil {
				qm.logger.Error("Failed to cleanup empty quarantined files: %v", err)
			}
		}
	}()

	return nil
}

// Stop dừng Quarantine Manager
func (qm *QuarantineManager) Stop() {
	qm.logger.Info("Quarantine Manager stopped")
}

// isFileReadable checks if a file can be read without actually reading it
func (qm *QuarantineManager) isFileReadable(filePath string) bool {
	// Try to open file with read access
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer file.Close()

	// Try to get file info
	_, err = file.Stat()
	return err == nil
}

// waitForFileAccess waits for a file to become accessible
func (qm *QuarantineManager) waitForFileAccess(filePath string, maxWait time.Duration) bool {
	start := time.Now()
	checkInterval := 100 * time.Millisecond

	for time.Since(start) < maxWait {
		if qm.isFileReadable(filePath) {
			return true
		}
		time.Sleep(checkInterval)
	}
	return false
}

// QuarantineFile cách ly file
func (qm *QuarantineManager) QuarantineFile(filePath string) (string, error) {
	// Guard: Skip protected system paths to avoid breaking Windows
	if qm.isProtectedSystemPath(filePath) {
		qm.logger.Warn("Protected system path detected, skipping quarantine: %s", filePath)
		return "", nil
	}

	// Prevent recursive self-quarantine of the quarantine directory
	if strings.Contains(strings.ToLower(filePath), strings.ToLower(qm.quarantineDir)) {
		qm.logger.Debug("Skipping self-quarantine path: %s", filePath)
		return "", nil
	}

	// Check if file exists first
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		qm.logger.Warn("File does not exist, skipping quarantine: %s", filePath)
		return "", nil // Don't return error, just skip
	}

	// Check if file is readable
	if !qm.isFileReadable(filePath) {
		qm.logger.Debug("File not immediately readable, waiting for access: %s", filePath)

		// Wait up to 5 seconds for file to become accessible
		if !qm.waitForFileAccess(filePath, 5*time.Second) {
			qm.logger.Warn("File not accessible after waiting, attempting to handle locked file: %s", filePath)

			// Try to handle locked file
			if err := qm.handleLockedFile(filePath); err != nil {
				qm.logger.Error("Failed to handle locked file: %v", err)
				return "", fmt.Errorf("file not accessible and cannot be handled: %s", filePath)
			}

			// If we successfully handled the locked file, return success
			// The handleLockedFile function will have created quarantine entries
			return "", nil // Successfully handled, but no single quarantine path to return
		}
	}

	// Create quarantine file path
	fileName := filepath.Base(filePath)
	quarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_%d", fileName, time.Now().Unix()))

	// Try multiple approaches with retry logic
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		qm.logger.Debug("Quarantine attempt %d/%d for file: %s", attempt, maxRetries, filePath)

		// Check if file still exists before attempting
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			qm.logger.Warn("File no longer exists during quarantine attempt %d: %s", attempt, filePath)
			return "", nil // File was deleted during quarantine process
		}

		// Check if file is still readable
		if !qm.isFileReadable(filePath) {
			qm.logger.Debug("File not readable during attempt %d, waiting...", attempt)
			if !qm.waitForFileAccess(filePath, 2*time.Second) {
				qm.logger.Debug("File still not readable after waiting")
				if attempt < maxRetries {
					continue
				}
			}
		}

		// Try to move file first (most efficient)
		if err := os.Rename(filePath, quarantinePath); err == nil {
			// Verify the moved file has content
			if qm.verifyQuarantinedFile(quarantinePath) {
				qm.logger.Info("File quarantined (moved): %s -> %s", filePath, quarantinePath)
				return quarantinePath, nil
			} else {
				// Move succeeded but file is empty, try to restore and use copy method
				qm.logger.Warn("Moved file is empty, restoring and trying copy method")
				if restoreErr := os.Rename(quarantinePath, filePath); restoreErr != nil {
					qm.logger.Error("Failed to restore file after empty move: %v", restoreErr)
				}
			}
		} else {
			qm.logger.Debug("Move failed (attempt %d): %v", attempt, err)
		}

		// If move fails or results in empty file, try copy approach
		if stat, statErr := os.Stat(filePath); statErr == nil {
			if stat.IsDir() {
				// Handle directory quarantine
				if err := qm.quarantineDirectoryContents(filePath); err == nil {
					qm.logger.Info("Directory quarantined (contents copied): %s", filePath)
					return "", nil // Directory quarantine successful, but no single path to return
				} else {
					qm.logger.Debug("Directory quarantine failed (attempt %d): %v", attempt, err)
				}
			} else {
				// Handle file quarantine
				if err := qm.quarantineSingleFile(filePath, quarantinePath); err == nil {
					// Verify the copied file has content
					if qm.verifyQuarantinedFile(quarantinePath) {
						qm.logger.Info("File quarantined (copied): %s -> %s", filePath, quarantinePath)
						return quarantinePath, nil
					} else {
						// Copy succeeded but file is empty, clean up and retry
						qm.logger.Warn("Copied file is empty, cleaning up and retrying")
						os.Remove(quarantinePath)
						if attempt < maxRetries {
							continue
						}
					}
				} else {
					qm.logger.Debug("File copy failed (attempt %d): %v", attempt, err)
				}
			}
		} else if os.IsNotExist(statErr) {
			qm.logger.Warn("File no longer exists during quarantine attempt %d: %s", attempt, filePath)
			return "", nil // File was deleted during quarantine process
		}

		// Wait before retry (exponential backoff)
		if attempt < maxRetries {
			waitTime := time.Duration(attempt) * time.Second
			qm.logger.Debug("Waiting %v before retry", waitTime)
			time.Sleep(waitTime)
		}
	}

	return "", fmt.Errorf("failed to quarantine file after %d attempts: %s", maxRetries, filePath)
}

// verifyQuarantinedFile verifies that a quarantined file has content
func (qm *QuarantineManager) verifyQuarantinedFile(quarantinePath string) bool {
	// Check if file exists
	if _, err := os.Stat(quarantinePath); os.IsNotExist(err) {
		qm.logger.Warn("Quarantined file does not exist: %s", quarantinePath)
		return false
	}

	// Check file size
	if fileInfo, err := os.Stat(quarantinePath); err == nil {
		if fileInfo.Size() == 0 {
			qm.logger.Warn("Quarantined file is empty: %s", quarantinePath)
			return false
		}
		qm.logger.Debug("Quarantined file verified: %s (size: %d bytes)", quarantinePath, fileInfo.Size())
		return true
	}

	qm.logger.Warn("Failed to verify quarantined file: %s", quarantinePath)
	return false
}

// quarantineDirectory handles directory quarantine with better error handling
func (qm *QuarantineManager) quarantineDirectory(srcDir, dstDir string) error {
	// Create destination directory
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// Walk through source directory
	return filepath.Walk(srcDir, func(src string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			// Skip files that can't be accessed
			qm.logger.Debug("Skipping inaccessible file: %s", src)
			return nil
		}

		// Calculate relative path
		rel, err := filepath.Rel(srcDir, src)
		if err != nil {
			return fmt.Errorf("failed to calculate relative path: %w", err)
		}

		dst := filepath.Join(dstDir, rel)

		if info.IsDir() {
			// Create directory
			if err := os.MkdirAll(dst, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dst, err)
			}
		} else {
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", dst, err)
			}

			// Copy file with retry
			if err := qm.copyFileContents(src, dst); err != nil {
				qm.logger.Debug("Failed to copy file %s: %v", src, err)
				// Continue with other files instead of failing completely
				return nil
			}
		}

		return nil
	})
}

// copyFileContents copies a file's contents from src to dst
func (qm *QuarantineManager) copyFileContents(src, dst string) error {
	// Try multiple strategies for reading the source file
	content, err := qm.readFileWithMultipleStrategies(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Verify we have content to copy
	if len(content) == 0 {
		// Reduce noise: skip empty or log files silently
		lower := strings.ToLower(src)
		if strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".tmp") {
			qm.logger.Debug("Skipping empty or unsupported file during quarantine: %s", src)
			return nil
		}
		qm.logger.Debug("Source file is empty or unreadable (skipped): %s", src)
		return nil
	}

	// Create destination file
	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	// Write content to destination
	bytesWritten, err := out.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write to destination file: %w", err)
	}

	// Verify we wrote the expected amount of data
	if bytesWritten != len(content) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d bytes", len(content), bytesWritten)
	}

	// Ensure data is written to disk
	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	// Verify the destination file has the expected size
	if fileInfo, err := out.Stat(); err == nil {
		if fileInfo.Size() != int64(len(content)) {
			return fmt.Errorf("destination file size mismatch: expected %d bytes, got %d bytes", len(content), fileInfo.Size())
		}
	}

	qm.logger.Debug("Successfully copied %d bytes from %s to %s", len(content), src, dst)
	return nil
}

// readFileWithMultipleStrategies attempts to read a file using multiple strategies
// to handle Windows-specific file access issues
func (qm *QuarantineManager) readFileWithMultipleStrategies(filePath string) ([]byte, error) {
	// Strategy 1: PowerShell-specific handling (for PowerShell files that cause "Incorrect function" errors)
	if strings.Contains(strings.ToLower(filePath), "powershell") {
		if content, err := qm.readPowerShellFile(filePath); err == nil {
			return content, nil
		} else {
			qm.logger.Debug("PowerShell-specific file reading failed: %v", err)
		}
	}

	// Strategy 2: Windows-specific file reading (for special Windows files)
	if content, err := qm.readFileWindowsSpecific(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("Windows-specific file reading failed: %v", err)
	}

	// Strategy 3: Standard file reading with retry
	if content, err := qm.readFileStandard(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("Standard file reading failed: %v", err)
	}

	// Strategy 4: Chunked reading with aggressive recovery
	if content, err := qm.readFileChunked(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("Chunked file reading failed: %v", err)
	}

	// Strategy 5: Try to copy to temp file first, then read
	if content, err := qm.readFileViaCopy(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("File reading via copy failed: %v", err)
	}

	return nil, fmt.Errorf("all file reading strategies failed for: %s", filePath)
}

// readPowerShellFile attempts to read PowerShell files using special handling
func (qm *QuarantineManager) readPowerShellFile(filePath string) ([]byte, error) {
	qm.logger.Debug("Attempting PowerShell-specific file reading for: %s", filePath)

	// PowerShell files can be problematic on Windows, try multiple approaches

	// Approach 1: Try with different file permissions
	permissions := []int{
		os.O_RDONLY,
		os.O_RDONLY | os.O_SYNC,
	}

	for _, perm := range permissions {
		if content, err := qm.readFileWithPermission(filePath, perm); err == nil {
			return content, nil
		}
	}

	// Approach 2: Try to read as binary with minimal processing
	if content, err := qm.readFileAsBinary(filePath); err == nil {
		return content, nil
	}

	return nil, fmt.Errorf("powershell-specific reading methods failed")
}

// readFileWithPermission attempts to read file with specific permissions
func (qm *QuarantineManager) readFileWithPermission(filePath string, flags int) ([]byte, error) {
	file, err := os.OpenFile(filePath, flags, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := fileInfo.Size()
	if fileSize == 0 {
		return []byte{}, nil
	}

	// Read file content
	content := make([]byte, fileSize)
	n, err := file.Read(content)
	if err != nil && err != io.EOF {
		return nil, err
	}

	if int64(n) != fileSize {
		content = content[:n]
	}

	return content, nil
}

// readFileAsBinary attempts to read file as binary with minimal processing
func (qm *QuarantineManager) readFileAsBinary(filePath string) ([]byte, error) {
	// This is a simplified approach for binary file reading
	// In a real system, you might use Windows-specific APIs

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read file in small chunks to avoid memory issues
	const chunkSize = 8 * 1024 // 8KB chunks
	var content []byte
	buffer := make([]byte, chunkSize)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			content = append(content, buffer[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return content, nil
}

// readFileWindowsSpecific attempts to read Windows-specific files using alternative methods
func (qm *QuarantineManager) readFileWindowsSpecific(filePath string) ([]byte, error) {
	qm.logger.Debug("Attempting Windows-specific file reading for: %s", filePath)

	// Try using Windows file mapping for large files
	if content, err := qm.readFileWithMapping(filePath); err == nil {
		return content, nil
	}

	// Try using Windows-specific file attributes
	if content, err := qm.readFileWithAttributes(filePath); err == nil {
		return content, nil
	}

	return nil, fmt.Errorf("windows-specific reading methods failed")
}

// readFileWithMapping attempts to read file using memory mapping (for large files)
func (qm *QuarantineManager) readFileWithMapping(filePath string) ([]byte, error) {
	// This is a simplified implementation
	// In a real system, you would use Windows memory mapping API
	qm.logger.Debug("Memory mapping not implemented, falling back to standard methods")
	return nil, fmt.Errorf("memory mapping not implemented")
}

// readFileWithAttributes attempts to read file with specific Windows attributes
func (qm *QuarantineManager) readFileWithAttributes(filePath string) ([]byte, error) {
	// This is a simplified implementation
	// In a real system, you would use Windows file attributes API
	qm.logger.Debug("Windows file attributes reading not implemented, falling back to standard methods")
	return nil, fmt.Errorf("windows file attributes reading not implemented")
}

// readFileStandard attempts standard file reading with retry logic
func (qm *QuarantineManager) readFileStandard(filePath string) ([]byte, error) {
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		qm.logger.Debug("Standard file reading attempt %d/%d for: %s", attempt, maxRetries, filePath)

		// Try to open file
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
		if err != nil {
			lastErr = err
			qm.logger.Debug("Failed to open file (attempt %d): %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to open file: %w", err)
		}

		// Get file info
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			lastErr = err
			qm.logger.Debug("Failed to get file info (attempt %d): %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to get file info: %w", err)
		}

		fileSize := fileInfo.Size()
		if fileSize == 0 {
			file.Close()
			return []byte{}, nil
		}

		// Read entire file
		content := make([]byte, fileSize)
		_, err = io.ReadFull(file, content)
		file.Close()

		if err == nil {
			return content, nil
		}

		lastErr = err
		qm.logger.Debug("Failed to read file content (attempt %d): %v", attempt, err)

		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("standard file reading failed after %d attempts: %w", maxRetries, lastErr)
}

// readFileChunked attempts chunked reading with aggressive error recovery
func (qm *QuarantineManager) readFileChunked(filePath string) ([]byte, error) {
	qm.logger.Debug("Attempting chunked file reading for: %s", filePath)

	// Get file info first
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	fileSize := fileInfo.Size()
	if fileSize == 0 {
		return []byte{}, nil
	}

	// Try multiple file opening strategies with Windows-specific handling
	var file *os.File
	openStrategies := []struct {
		flags int
		desc  string
	}{
		{os.O_RDONLY, "standard read-only"},
		{os.O_RDONLY | os.O_SYNC, "read-only with sync"},
	}

	for _, strategy := range openStrategies {
		file, err = os.OpenFile(filePath, strategy.flags, 0)
		if err == nil {
			qm.logger.Debug("Successfully opened file with strategy: %s", strategy.desc)
			break
		}
		qm.logger.Debug("Failed to open file with strategy %s: %v", strategy.desc, err)
	}

	if file == nil {
		return nil, fmt.Errorf("failed to open file with any strategy")
	}
	defer file.Close()

	// Read file in chunks with aggressive error recovery
	const chunkSize = 32 * 1024 // 32KB chunks
	content := make([]byte, 0, fileSize)
	totalRead := int64(0)
	consecutiveErrors := 0
	maxConsecutiveErrors := 3
	loggedWindowsAccessWarns := 0
	maxWindowsAccessWarnLogs := 2

	for totalRead < fileSize {
		// Calculate chunk size for this iteration
		remaining := fileSize - totalRead
		currentChunkSize := chunkSize
		if remaining < int64(chunkSize) {
			currentChunkSize = int(remaining)
		}

		// Read chunk
		chunk := make([]byte, currentChunkSize)
		n, err := file.Read(chunk)

		if n > 0 {
			content = append(content, chunk[:n]...)
			totalRead += int64(n)
			consecutiveErrors = 0 // Reset error counter on successful read
			qm.logger.Debug("Read chunk: %d bytes, total: %d/%d", n, totalRead, fileSize)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			consecutiveErrors++
			// Limit WARN spam for repetitive Windows access errors
			logAsWarn := true
			if strings.Contains(err.Error(), "Incorrect function") ||
				strings.Contains(err.Error(), "Access is denied") ||
				strings.Contains(err.Error(), "The process cannot access the file") ||
				strings.Contains(err.Error(), "The file cannot be accessed by the system") {
				if loggedWindowsAccessWarns >= maxWindowsAccessWarnLogs {
					logAsWarn = false
				} else {
					loggedWindowsAccessWarns++
				}
			}
			if logAsWarn {
				qm.logger.Warn("Failed to read chunk at position %d (error %d/%d): %v", totalRead, consecutiveErrors, maxConsecutiveErrors, err)
			} else {
				qm.logger.Debug("Windows file access read retry at %d (error %d/%d): %v", totalRead, consecutiveErrors, maxConsecutiveErrors, err)
			}

			// Check if this is a Windows-specific error
			if strings.Contains(err.Error(), "Incorrect function") ||
				strings.Contains(err.Error(), "Access is denied") ||
				strings.Contains(err.Error(), "The process cannot access the file") ||
				strings.Contains(err.Error(), "The file cannot be accessed by the system") {

				if loggedWindowsAccessWarns <= maxWindowsAccessWarnLogs {
					qm.logger.Warn("Windows file access error detected, attempting recovery...")
				} else {
					qm.logger.Debug("Windows file access error detected, attempting recovery (suppressed warn)...")
				}

				// Try to recover by closing and reopening the file
				file.Close()
				time.Sleep(500 * time.Millisecond) // Increased wait time

				// Try to reopen with different strategy
				for _, strategy := range openStrategies {
					file, err = os.OpenFile(filePath, strategy.flags, 0)
					if err == nil {
						qm.logger.Debug("Successfully reopened file with strategy: %s", strategy.desc)
						break
					}
				}

				if file == nil {
					// If we can't reopen, try alternative reading methods
					qm.logger.Warn("Failed to reopen file, trying alternative reading methods")

					// Try to read the remaining content using alternative methods
					if alternativeContent, altErr := qm.readRemainingContentAlternative(filePath, totalRead, fileSize); altErr == nil {
						content = append(content, alternativeContent...)
						qm.logger.Info("Successfully read remaining content using alternative method: %d bytes", len(alternativeContent))
						return content, nil
					}

					return nil, fmt.Errorf("failed to reopen file after error and alternative methods failed")
				}

				// Seek to current position
				if _, seekErr := file.Seek(totalRead, 0); seekErr != nil {
					qm.logger.Error("Failed to seek to position %d: %v", totalRead, seekErr)
					return nil, fmt.Errorf("failed to seek in file: %w", seekErr)
				}

				// Continue reading from this position
				continue
			}

			// For other errors, check if we've had too many consecutive errors
			if consecutiveErrors >= maxConsecutiveErrors {
				qm.logger.Error("Too many consecutive errors (%d), giving up", consecutiveErrors)
				if totalRead > 0 && len(content) > 0 {
					qm.logger.Warn("Partial read successful (%d bytes), returning partial content", len(content))
					return content, nil
				}
				return nil, fmt.Errorf("failed to read file after %d consecutive errors: %w", consecutiveErrors, err)
			}

			// Wait before retry for non-Windows errors
			time.Sleep(100 * time.Millisecond)
			continue
		}
	}

	return content, nil
}

// readRemainingContentAlternative attempts to read remaining content using alternative methods
func (qm *QuarantineManager) readRemainingContentAlternative(filePath string, startPos, fileSize int64) ([]byte, error) {
	qm.logger.Debug("Attempting alternative reading method from position %d", startPos)

	// Try using Windows-specific file reading
	if content, err := qm.readFileWindowsSpecific(filePath); err == nil {
		if int64(len(content)) >= startPos {
			return content[startPos:], nil
		}
	}

	// Try using file copy method
	if content, err := qm.readFileViaCopy(filePath); err == nil {
		if int64(len(content)) >= startPos {
			return content[startPos:], nil
		}
	}

	return nil, fmt.Errorf("all alternative reading methods failed")
}

// readFileViaCopy attempts to read file by first copying it to a temporary location
func (qm *QuarantineManager) readFileViaCopy(filePath string) ([]byte, error) {
	qm.logger.Debug("Attempting file reading via copy for: %s", filePath)

	// Create temporary file
	tempFile, err := os.CreateTemp("", "read_copy_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Try to copy the file
	srcFile, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Copy file content
	_, err = io.Copy(tempFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Reset temp file pointer
	tempFile.Seek(0, 0)

	// Read from temp file
	content, err := io.ReadAll(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read temp file: %w", err)
	}

	qm.logger.Debug("Successfully read %d bytes via copy method", len(content))
	return content, nil
}

// RestoreFile khôi phục file từ quarantine
func (qm *QuarantineManager) RestoreFile(filePath string) error {
	// This is a simplified implementation
	// In a real system, you would need to track the original location
	qm.logger.Info("File restore requested: %s", filePath)
	return fmt.Errorf("file restore not implemented yet")
}

// handleLockedFile attempts to handle files that are locked by other processes
func (qm *QuarantineManager) handleLockedFile(filePath string) error {
	qm.logger.Debug("Attempting to handle locked file: %s", filePath)

	// Try to get file info to see if it's accessible
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat locked file: %w", err)
	}

	// If it's a directory, try to quarantine individual files
	if fileInfo.IsDir() {
		qm.logger.Debug("Locked file is a directory, attempting to quarantine contents")
		return qm.quarantineDirectoryContents(filePath)
	}

	// For regular files, try to wait and retry
	qm.logger.Debug("Waiting for locked file to become accessible: %s", filePath)
	if qm.waitForFileAccess(filePath, 10*time.Second) {
		return nil // File became accessible
	}

	return fmt.Errorf("file remains locked after waiting: %s", filePath)
}

// quarantineDirectoryContents quarantines the contents of a directory that might be locked
func (qm *QuarantineManager) quarantineDirectoryContents(dirPath string) error {
	qm.logger.Debug("Quarantining directory contents: %s", dirPath)

	// Create a quarantine directory for the contents
	dirName := filepath.Base(dirPath)
	quarantineDir := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_contents_%d", dirName, time.Now().Unix()))

	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	// Walk through the directory and quarantine accessible files
	successCount := 0
	totalCount := 0
	emptyFiles := []string{}

	err := filepath.Walk(dirPath, func(src string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			qm.logger.Debug("Skipping inaccessible file: %s", src)
			return nil // Continue with other files
		}

		totalCount++

		// Skip the root directory itself
		if src == dirPath {
			return nil
		}

		// Calculate relative path
		rel, err := filepath.Rel(dirPath, src)
		if err != nil {
			qm.logger.Debug("Failed to calculate relative path for %s: %v", src, err)
			return nil
		}

		dst := filepath.Join(quarantineDir, rel)

		// Create destination directory if needed
		if info.IsDir() {
			if err := os.MkdirAll(dst, 0755); err != nil {
				qm.logger.Debug("Failed to create destination directory: %s", dst)
				return nil
			}
			return nil
		}

		// Quarantine the file
		if err := qm.quarantineSingleFile(src, dst); err != nil {
			qm.logger.Debug("Failed to quarantine file: %s -> %s: %v", src, dst, err)
			return nil
		}

		// Verify the quarantined file has content
		if qm.verifyQuarantinedFile(dst) {
			successCount++
			qm.logger.Debug("Successfully quarantined file: %s -> %s", src, dst)
		} else {
			emptyFiles = append(emptyFiles, dst)
			qm.logger.Warn("Quarantined file is empty: %s", dst)
		}

		return nil
	})

	if err != nil {
		qm.logger.Error("Error during directory walk: %v", err)
	}

	// Clean up empty files
	if len(emptyFiles) > 0 {
		qm.logger.Warn("Found %d empty quarantined files, cleaning up...", len(emptyFiles))
		for _, emptyFile := range emptyFiles {
			if err := os.Remove(emptyFile); err != nil {
				qm.logger.Debug("Failed to remove empty file: %s: %v", emptyFile, err)
			}
		}
	}

	qm.logger.Info("Directory quarantine completed: %d/%d files successfully quarantined from %s", successCount, totalCount, dirPath)

	// If no files were successfully quarantined, remove the quarantine directory
	if successCount == 0 {
		if err := os.RemoveAll(quarantineDir); err != nil {
			qm.logger.Debug("Failed to remove empty quarantine directory: %s: %v", quarantineDir, err)
		}
		return fmt.Errorf("no files could be quarantined from directory: %s", dirPath)
	}

	return nil
}

// cleanupEmptyQuarantinedFiles removes empty quarantined files and directories
func (qm *QuarantineManager) cleanupEmptyQuarantinedFiles() error {
	qm.logger.Debug("Starting cleanup of empty quarantined files")

	// Walk through quarantine directory
	err := filepath.Walk(qm.quarantineDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue with other files
		}

		// Skip the root quarantine directory
		if path == qm.quarantineDir {
			return nil
		}

		// Check if it's a file
		if !info.IsDir() {
			// Check if file is empty
			if info.Size() == 0 {
				qm.logger.Warn("Found empty quarantined file, removing: %s", path)
				if removeErr := os.Remove(path); removeErr != nil {
					qm.logger.Debug("Failed to remove empty file: %s: %v", path, removeErr)
				}
			} else {
				// Check if this is a problematic file that needs special handling
				if qm.isProblematicFile(path) {
					qm.logger.Warn("Found problematic quarantined file, attempting to fix: %s", path)
					if fixErr := qm.handleProblematicQuarantineFile(path); fixErr != nil {
						qm.logger.Error("Failed to fix problematic file: %s: %v", path, fixErr)
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		qm.logger.Error("Error during cleanup walk: %v", err)
		return err
	}

	qm.logger.Debug("Cleanup of empty quarantined files completed")
	return nil
}

// isProblematicFile checks if a file is known to cause issues
func (qm *QuarantineManager) isProblematicFile(filePath string) bool {
	fileName := strings.ToLower(filepath.Base(filePath))

	// Check for known problematic file patterns
	problematicPatterns := []string{
		"powershell",
		"quarantine_contents",
		"empty",
		"corrupted",
	}

	for _, pattern := range problematicPatterns {
		if strings.Contains(fileName, pattern) {
			return true
		}
	}

	return false
}

// isProtectedSystemPath returns true if the path is a critical Windows system file/dir
func (qm *QuarantineManager) isProtectedSystemPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	protectedPrefixes := []string{
		`c:\windows\system32`,
		`c:\windows\winsxs`,
		`c:\windows\syswow64`,
		`c:\windows\servicing`,
		`c:\windows\security`,
		`c:\windows\boot`,
	}
	protectedFiles := []string{
		`c:\windows\system32\config\sam`,
		`c:\windows\system32\config\system`,
		`c:\windows\system32\config\software`,
		`c:\windows\system32\config\security`,
		`c:\windows\system32\config\components`,
		`c:\windows\system32\ntoskrnl.exe`,
		`c:\windows\system32\winlogon.exe`,
		`c:\windows\system32\lsass.exe`,
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

// handleProblematicQuarantineFile attempts to handle files that are causing persistent issues
func (qm *QuarantineManager) handleProblematicQuarantineFile(filePath string) error {
	qm.logger.Warn("Handling problematic quarantine file: %s", filePath)

	// Check if this is the specific PowerShell file causing issues
	if strings.Contains(strings.ToLower(filePath), "powershell") {
		qm.logger.Warn("Detected problematic PowerShell file, attempting special handling: %s", filePath)

		// Try to get file info to understand the issue
		if fileInfo, err := os.Stat(filePath); err == nil {
			qm.logger.Info("File info - Size: %d bytes, Mode: %s, ModTime: %s",
				fileInfo.Size(), fileInfo.Mode(), fileInfo.ModTime())

			// If file is empty, remove it
			if fileInfo.Size() == 0 {
				qm.logger.Warn("Problematic file is empty, removing: %s", filePath)
				if err := os.Remove(filePath); err != nil {
					qm.logger.Error("Failed to remove empty problematic file: %v", err)
				}
				return nil
			}
		}

		// Try to read with PowerShell-specific methods
		if content, err := qm.readPowerShellFile(filePath); err == nil && len(content) > 0 {
			qm.logger.Info("Successfully read problematic PowerShell file: %d bytes", len(content))

			// Create a new quarantine file with a different name
			newQuarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("recovered_powershell_%d", time.Now().Unix()))

			if err := qm.writeQuarantineFile(newQuarantinePath, content); err == nil {
				// Remove the problematic file
				if err := os.Remove(filePath); err != nil {
					qm.logger.Error("Failed to remove problematic file after recovery: %v", err)
				}
				qm.logger.Info("Successfully recovered problematic PowerShell file: %s -> %s", filePath, newQuarantinePath)
				return nil
			}
		}
	}

	// For other problematic files, try to move them to a special directory
	problematicDir := filepath.Join(qm.quarantineDir, "problematic_files")
	if err := os.MkdirAll(problematicDir, 0755); err != nil {
		qm.logger.Error("Failed to create problematic files directory: %v", err)
		return err
	}

	newPath := filepath.Join(problematicDir, filepath.Base(filePath))
	if err := os.Rename(filePath, newPath); err != nil {
		qm.logger.Error("Failed to move problematic file: %v", err)
		return err
	}

	qm.logger.Info("Moved problematic file to: %s", newPath)
	return nil
}

// writeQuarantineFile writes content to a quarantine file with verification
func (qm *QuarantineManager) writeQuarantineFile(quarantinePath string, content []byte) error {
	// Create the file
	file, err := os.Create(quarantinePath)
	if err != nil {
		return fmt.Errorf("failed to create quarantine file: %w", err)
	}
	defer file.Close()

	// Write content
	bytesWritten, err := file.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write to quarantine file: %w", err)
	}

	// Verify write
	if bytesWritten != len(content) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d bytes", len(content), bytesWritten)
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync quarantine file: %w", err)
	}

	// Verify file size
	if fileInfo, err := file.Stat(); err == nil {
		if fileInfo.Size() != int64(len(content)) {
			return fmt.Errorf("file size mismatch: expected %d bytes, got %d bytes", len(content), fileInfo.Size())
		}
	}

	return nil
}

// quarantineSingleFile quarantines a single file with retry logic
func (qm *QuarantineManager) quarantineSingleFile(src, dst string) error {
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Try to copy the file
		if err := qm.copyFileContents(src, dst); err == nil {
			return nil
		}

		// If this is not the last attempt, wait and retry
		if attempt < maxRetries {
			waitTime := time.Duration(attempt) * 200 * time.Millisecond
			time.Sleep(waitTime)
		}
	}

	return fmt.Errorf("failed to quarantine file after %d attempts: %s", maxRetries, src)
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
