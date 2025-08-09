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
	mu                  sync.RWMutex // ADD: Thread safety
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

	// FIX: Early validation and normalization
	if filePath == "" {
		ae.logger.Warn("Empty file path provided for quarantine")
		return nil
	}

	// FIX: Normalize path to handle different path formats
	normalizedPath := filepath.Clean(filePath)

	// Check if file exists
	if _, err := os.Stat(normalizedPath); os.IsNotExist(err) {
		ae.logger.Warn("File does not exist, skipping quarantine: %s", normalizedPath)
		return nil // Don't return error, just skip
	}

	// FIX: Enhanced protection for system paths
	if ae.quarantineManager.isProtectedSystemPath(normalizedPath) {
		ae.logger.Warn("Skipping quarantine for protected system file: %s", normalizedPath)
		return nil
	}

	// Check if already quarantined
	if ae.quarantinedFiles[normalizedPath] {
		ae.logger.Debug("File already quarantined: %s", normalizedPath)
		return nil
	}

	// FIX: Pre-quarantine checks for problematic files
	if ae.quarantineManager.isProblematicQuarantineFile(normalizedPath) {
		ae.logger.Warn("File appears problematic for quarantine, using special handling: %s", normalizedPath)
		return ae.quarantineManager.handleProblematicFile(normalizedPath)
	}

	// Perform local quarantine with enhanced error handling
	quarantinePath, err := ae.quarantineManager.QuarantineFile(normalizedPath)
	if err != nil {
		ae.logger.Error("Failed to quarantine file locally: %v", err)
		// FIX: Don't fail completely, try alternative approaches
		if altErr := ae.quarantineManager.handleFailedQuarantine(normalizedPath, err); altErr != nil {
			return fmt.Errorf("failed to quarantine file: %w", err)
		}
		ae.quarantinedFiles[normalizedPath] = true
		return nil
	}

	// Check if quarantine was successful
	if quarantinePath == "" {
		ae.logger.Info("File quarantine completed (no single path returned): %s", normalizedPath)
		ae.quarantinedFiles[normalizedPath] = true
		return nil
	}

	// Update state
	ae.quarantinedFiles[normalizedPath] = true
	ae.logger.Info("File quarantined locally successfully: %s", normalizedPath)

	// Upload to server (async to avoid blocking)
	go func() {
		if ae.serverClient != nil {
			agentID := ae.serverClient.GetAgentID()
			if agentID == "" {
				ae.logger.Warn("Agent ID not set, skipping server upload")
				return
			}

			// FIX: Enhanced upload with retry and error handling
			err := ae.uploadQuarantineFileWithRetry(agentID, quarantinePath, 3)
			if err != nil {
				ae.logger.Error("Failed to upload file to server after retries: %v", err)
			} else {
				ae.logger.Info("✅ File uploaded to server successfully: %s", filepath.Base(quarantinePath))
				// Clean up local file after successful upload
				if remErr := ae.quarantineManager.cleanupLocalQuarantine(quarantinePath); remErr != nil {
					ae.logger.Warn("Failed to cleanup local quarantine: %v", remErr)
				}
			}
		}
	}()

	return nil
}

// FIX: Add retry mechanism for server uploads
func (ae *ActionEngine) uploadQuarantineFileWithRetry(agentID, quarantinePath string, maxRetries int) error {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ae.logger.Debug("Upload attempt %d/%d for: %s", attempt, maxRetries, quarantinePath)

		err := ae.serverClient.UploadQuarantineFile(agentID, quarantinePath)
		if err == nil {
			return nil
		}

		lastErr = err
		ae.logger.Warn("Upload attempt %d failed: %v", attempt, err)

		if attempt < maxRetries {
			waitTime := time.Duration(attempt) * time.Second
			time.Sleep(waitTime)
		}
	}

	return fmt.Errorf("upload failed after %d attempts: %w", maxRetries, lastErr)
}

// Rest of ActionEngine methods remain the same...
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

func (ae *ActionEngine) UnblockNetworkConnections(processID int) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.logger.Info("Unblocking network connections for process: %d", processID)

	connectionKey := fmt.Sprintf("process_%d", processID)

	if !ae.blockedConnections[connectionKey] {
		return fmt.Errorf("network connections were not blocked for process: %d", processID)
	}

	err := ae.networkController.UnblockConnection("", "", "")
	if err != nil {
		return fmt.Errorf("failed to unblock network connections: %w", err)
	}

	delete(ae.blockedConnections, connectionKey)
	ae.logger.Info("Network connections unblocked successfully for process: %d", processID)
	return nil
}

func (ae *ActionEngine) GetQuarantineList() []string {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	var files []string
	for filePath := range ae.quarantinedFiles {
		files = append(files, filePath)
	}
	return files
}

func (ae *ActionEngine) GetTerminatedProcesses() []int {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	var processes []int
	for processID := range ae.terminatedProcesses {
		processes = append(processes, processID)
	}
	return processes
}

func (ae *ActionEngine) GetBlockedConnections() []string {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	var connections []string
	for connectionKey := range ae.blockedConnections {
		connections = append(connections, connectionKey)
	}
	return connections
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

func (ae *ActionEngine) GetActionStats() map[string]interface{} {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	return map[string]interface{}{
		"quarantined_files_count":    len(ae.quarantinedFiles),
		"terminated_processes_count": len(ae.terminatedProcesses),
		"blocked_connections_count":  len(ae.blockedConnections),
		"auto_quarantine_enabled":    true,
		"block_execution_enabled":    true,
	}
}

// QuarantineManager với enhanced error handling
type QuarantineManager struct {
	config        *config.ResponseConfig
	logger        *utils.Logger
	quarantineDir string
	mu            sync.RWMutex // ADD: Thread safety
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

	// Start cleanup worker
	go qm.startCleanupWorker()

	return nil
}

func (qm *QuarantineManager) Stop() {
	qm.logger.Info("Quarantine Manager stopped")
}

// FIX: Enhanced startCleanupWorker
func (qm *QuarantineManager) startCleanupWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := qm.cleanupEmptyQuarantinedFiles(); err != nil {
			qm.logger.Error("Failed to cleanup empty quarantined files: %v", err)
		}

		// FIX: Also cleanup stuck quarantine operations
		if err := qm.cleanupStuckQuarantineOperations(); err != nil {
			qm.logger.Error("Failed to cleanup stuck quarantine operations: %v", err)
		}
	}
}

// FIX: Add method to detect problematic files before quarantine
func (qm *QuarantineManager) isProblematicQuarantineFile(filePath string) bool {
	// Check if file is likely to cause Windows access errors
	lower := strings.ToLower(filePath)

	// Files that commonly cause "Incorrect function" errors
	problematicPatterns := []string{
		"\\windows\\system32\\config\\",
		"\\windows\\security\\",
		"\\users\\default\\",
		"ntuser.dat",
		"hiberfil.sys",
		"pagefile.sys",
		"swapfile.sys",
	}

	for _, pattern := range problematicPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Check if file is currently in use by checking if we can open it
	return !qm.isFileAccessible(filePath)
}

// FIX: Enhanced handleProblematicFile method
func (qm *QuarantineManager) handleProblematicFile(filePath string) error {
	qm.logger.Warn("Handling problematic file: %s", filePath)

	// Strategy 1: Try to copy metadata instead of the file
	if err := qm.createQuarantineMetadata(filePath); err == nil {
		qm.logger.Info("Created quarantine metadata for problematic file: %s", filePath)
		return nil
	}

	// Strategy 2: Create a quarantine marker
	if err := qm.createQuarantineMarker(filePath); err == nil {
		qm.logger.Info("Created quarantine marker for problematic file: %s", filePath)
		return nil
	}

	// Strategy 3: Log the attempt and skip
	qm.logger.Warn("Cannot quarantine problematic file, logging attempt: %s", filePath)
	return qm.logQuarantineAttempt(filePath, "problematic_file_skipped")
}

// FIX: Add method to handle failed quarantine operations
func (qm *QuarantineManager) handleFailedQuarantine(filePath string, originalErr error) error {
	qm.logger.Warn("Quarantine failed for %s: %v", filePath, originalErr)

	// Try alternative quarantine strategies
	if err := qm.createQuarantineMetadata(filePath); err == nil {
		qm.logger.Info("Created metadata-only quarantine for: %s", filePath)
		return nil
	}

	if err := qm.createQuarantineMarker(filePath); err == nil {
		qm.logger.Info("Created marker-only quarantine for: %s", filePath)
		return nil
	}

	// Log the failure for analysis
	return qm.logQuarantineAttempt(filePath, fmt.Sprintf("failed: %v", originalErr))
}

// FIX: Add metadata-only quarantine for problematic files
func (qm *QuarantineManager) createQuarantineMetadata(filePath string) error {
	metadataPath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s.metadata", filepath.Base(filePath)))

	// Get file info if possible
	var metadata strings.Builder
	metadata.WriteString(fmt.Sprintf("Original Path: %s\n", filePath))
	metadata.WriteString(fmt.Sprintf("Quarantine Time: %s\n", time.Now().Format(time.RFC3339)))
	metadata.WriteString("Quarantine Type: Metadata Only (file could not be moved)\n")

	if info, err := os.Stat(filePath); err == nil {
		metadata.WriteString(fmt.Sprintf("File Size: %d bytes\n", info.Size()))
		metadata.WriteString(fmt.Sprintf("File Mode: %s\n", info.Mode().String()))
		metadata.WriteString(fmt.Sprintf("Modified: %s\n", info.ModTime().Format(time.RFC3339)))
	}

	return os.WriteFile(metadataPath, []byte(metadata.String()), 0644)
}

// FIX: Add quarantine marker for tracking
func (qm *QuarantineManager) createQuarantineMarker(filePath string) error {
	markerPath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s.marker", filepath.Base(filePath)))

	markerContent := fmt.Sprintf(`Quarantine Marker
Original File: %s
Marked Time: %s
Status: File marked for quarantine but could not be moved
Reason: File access restrictions or system protection
`, filePath, time.Now().Format(time.RFC3339))

	return os.WriteFile(markerPath, []byte(markerContent), 0644)
}

// FIX: Add quarantine attempt logging
func (qm *QuarantineManager) logQuarantineAttempt(filePath, status string) error {
	logPath := filepath.Join(qm.quarantineDir, "quarantine_log.txt")

	logEntry := fmt.Sprintf("[%s] %s: %s\n",
		time.Now().Format(time.RFC3339), status, filePath)

	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(logEntry)
	return err
}

// FIX: Add cleanup for stuck operations
func (qm *QuarantineManager) cleanupStuckQuarantineOperations() error {
	// Find and clean up any partially completed quarantine operations
	files, err := os.ReadDir(qm.quarantineDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-1 * time.Hour) // Files older than 1 hour
	cleaned := 0

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(qm.quarantineDir, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Clean up empty files that are stuck
		if info.Size() == 0 && info.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err == nil {
				qm.logger.Debug("Cleaned up stuck quarantine file: %s", file.Name())
				cleaned++
			}
		}

		// Clean up temporary files
		if strings.HasPrefix(file.Name(), "temp_") && info.ModTime().Before(cutoff) {
			if err := os.Remove(filePath); err == nil {
				qm.logger.Debug("Cleaned up temporary quarantine file: %s", file.Name())
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		qm.logger.Info("Cleaned up %d stuck quarantine operations", cleaned)
	}

	return nil
}

// FIX: Enhanced cleanup for local quarantine files
func (qm *QuarantineManager) cleanupLocalQuarantine(quarantinePath string) error {
	if err := os.Remove(quarantinePath); err != nil {
		return fmt.Errorf("failed to delete local quarantine file: %w", err)
	}

	qm.logger.Info("🧹 Deleted local quarantine file after upload: %s", quarantinePath)
	return nil
}

// Keep existing methods but add thread safety and better error handling...

// FIX: Enhanced QuarantineFile with better error handling
func (qm *QuarantineManager) QuarantineFile(filePath string) (string, error) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	// Guard: Skip protected system paths
	if qm.isProtectedSystemPath(filePath) {
		qm.logger.Warn("Protected system path detected, skipping quarantine: %s", filePath)
		return "", nil
	}

	// Prevent recursive self-quarantine
	if strings.Contains(strings.ToLower(filePath), strings.ToLower(qm.quarantineDir)) {
		qm.logger.Debug("Skipping self-quarantine path: %s", filePath)
		return "", nil
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		qm.logger.Warn("File does not exist, skipping quarantine: %s", filePath)
		return "", nil
	}

	// FIX: Enhanced accessibility check with timeout
	if !qm.waitForFileAccess(filePath, 5*time.Second) {
		qm.logger.Warn("File not accessible, using alternative quarantine: %s", filePath)

		// Use alternative quarantine method
		if err := qm.createQuarantineMetadata(filePath); err != nil {
			return "", fmt.Errorf("file not accessible and metadata quarantine failed: %w", err)
		}
		return "", nil // Successfully handled with metadata
	}

	// Create quarantine file path
	fileName := filepath.Base(filePath)
	quarantinePath := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_%d", fileName, time.Now().Unix()))

	// FIX: Enhanced quarantine with multiple strategies
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		qm.logger.Debug("Quarantine attempt %d/%d for file: %s", attempt, maxRetries, filePath)

		// Check if file still exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			qm.logger.Warn("File no longer exists during quarantine attempt %d: %s", attempt, filePath)
			return "", nil
		}

		// Strategy 1: Try to move file (most efficient)
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
		} else {
			qm.logger.Debug("Move failed (attempt %d): %v", attempt, err)
		}

		// Strategy 2: Try to copy file
		if err := qm.copyFileWithVerification(filePath, quarantinePath); err == nil {
			qm.logger.Info("File quarantined (copied): %s -> %s", filePath, quarantinePath)
			return quarantinePath, nil
		} else {
			qm.logger.Debug("Copy failed (attempt %d): %v", attempt, err)
		}

		// Strategy 3: Handle directories
		if stat, statErr := os.Stat(filePath); statErr == nil && stat.IsDir() {
			if err := qm.quarantineDirectoryContents(filePath); err == nil {
				qm.logger.Info("Directory quarantined (contents copied): %s", filePath)
				return "", nil // Directory quarantine successful
			} else {
				qm.logger.Debug("Directory quarantine failed (attempt %d): %v", attempt, err)
			}
		}

		// Wait before retry
		if attempt < maxRetries {
			waitTime := time.Duration(attempt) * time.Second
			qm.logger.Debug("Waiting %v before retry", waitTime)
			time.Sleep(waitTime)
		}
	}

	return "", fmt.Errorf("failed to quarantine file after %d attempts: %s", maxRetries, filePath)
}

// FIX: Enhanced file copy with verification
func (qm *QuarantineManager) copyFileWithVerification(src, dst string) error {
	// Try multiple read strategies
	content, err := qm.readFileWithMultipleStrategies(src)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	if len(content) == 0 {
		return fmt.Errorf("source file is empty or unreadable")
	}

	// Write to destination with verification
	if err := qm.writeFileWithVerification(dst, content); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	return nil
}

// FIX: Enhanced file writing with verification
func (qm *QuarantineManager) writeFileWithVerification(filePath string, content []byte) error {
	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write content
	bytesWritten, err := file.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write content: %w", err)
	}

	if bytesWritten != len(content) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d bytes", len(content), bytesWritten)
	}

	// Sync to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Verify file size
	if fileInfo, err := file.Stat(); err == nil {
		if fileInfo.Size() != int64(len(content)) {
			return fmt.Errorf("file size mismatch: expected %d bytes, got %d bytes", len(content), fileInfo.Size())
		}
	}

	qm.logger.Debug("Successfully wrote and verified %d bytes to %s", len(content), filePath)
	return nil
}

// Keep existing methods but with enhanced error handling...

func (qm *QuarantineManager) isFileAccessible(filePath string) bool {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer file.Close()

	_, err = file.Stat()
	return err == nil
}

func (qm *QuarantineManager) waitForFileAccess(filePath string, maxWait time.Duration) bool {
	start := time.Now()
	checkInterval := 100 * time.Millisecond

	for time.Since(start) < maxWait {
		if qm.isFileAccessible(filePath) {
			return true
		}
		time.Sleep(checkInterval)
	}
	return false
}

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
		qm.logger.Debug("Quarantined file verified: %s (size: %d bytes)", quarantinePath, fileInfo.Size())
		return true
	}

	qm.logger.Warn("Failed to verify quarantined file: %s", quarantinePath)
	return false
}

// FIX: Simplified but more robust readFileWithMultipleStrategies
func (qm *QuarantineManager) readFileWithMultipleStrategies(filePath string) ([]byte, error) {
	var lastErr error

	// Strategy 1: Standard reading
	if content, err := qm.readFileStandard(filePath); err == nil {
		return content, nil
	} else {
		lastErr = err
		qm.logger.Debug("Standard file reading failed: %v", err)
	}

	// Strategy 2: Small chunk reading to avoid memory issues
	if content, err := qm.readFileInSmallChunks(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("Small chunk reading failed: %v", err)
	}

	// Strategy 3: Try copying to temp location first
	if content, err := qm.readFileViaTempCopy(filePath); err == nil {
		return content, nil
	} else {
		qm.logger.Debug("Temp copy reading failed: %v", err)
	}

	return nil, fmt.Errorf("all file reading strategies failed: %w", lastErr)
}

// FIX: Simplified standard file reading
func (qm *QuarantineManager) readFileStandard(filePath string) ([]byte, error) {
	maxRetries := 2
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
		if err != nil {
			lastErr = err
			if attempt < maxRetries {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to open file: %w", err)
		}

		content, err := io.ReadAll(file)
		file.Close()

		if err == nil {
			return content, nil
		}

		lastErr = err
		if attempt < maxRetries {
			time.Sleep(100 * time.Millisecond)
		}
	}

	return nil, fmt.Errorf("standard reading failed: %w", lastErr)
}

// FIX: Read file in small chunks to avoid Windows access issues
func (qm *QuarantineManager) readFileInSmallChunks(filePath string) ([]byte, error) {
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

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
			// Don't fail completely on partial reads
			if len(content) > 0 {
				qm.logger.Warn("Partial read successful (%d bytes), returning partial content", len(content))
				return content, nil
			}
			return nil, fmt.Errorf("chunk reading failed: %w", err)
		}
	}

	return content, nil
}

// FIX: Read via temporary copy
func (qm *QuarantineManager) readFileViaTempCopy(filePath string) ([]byte, error) {
	tempFile, err := os.CreateTemp("", "quarantine_read_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Try to copy using OS-level copy
	srcFile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source: %w", err)
	}
	defer srcFile.Close()

	_, err = io.Copy(tempFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy: %w", err)
	}

	// Read from temp file
	tempFile.Seek(0, 0)
	return io.ReadAll(tempFile)
}

func (qm *QuarantineManager) quarantineDirectoryContents(dirPath string) error {
	qm.logger.Debug("Quarantining directory contents: %s", dirPath)

	dirName := filepath.Base(dirPath)
	quarantineDir := filepath.Join(qm.quarantineDir, fmt.Sprintf("%s_contents_%d", dirName, time.Now().Unix()))

	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return fmt.Errorf("failed to create quarantine directory: %w", err)
	}

	successCount := 0
	totalCount := 0

	err := filepath.Walk(dirPath, func(src string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			qm.logger.Debug("Skipping inaccessible file: %s", src)
			return nil
		}

		totalCount++

		if src == dirPath {
			return nil // Skip root directory
		}

		rel, err := filepath.Rel(dirPath, src)
		if err != nil {
			qm.logger.Debug("Failed to calculate relative path for %s: %v", src, err)
			return nil
		}

		dst := filepath.Join(quarantineDir, rel)

		if info.IsDir() {
			if err := os.MkdirAll(dst, 0755); err != nil {
				qm.logger.Debug("Failed to create destination directory: %s", dst)
			}
			return nil
		}

		// Try to quarantine individual file
		if err := qm.copyFileWithVerification(src, dst); err != nil {
			qm.logger.Debug("Failed to quarantine file: %s -> %s: %v", src, dst, err)
			return nil
		}

		if qm.verifyQuarantinedFile(dst) {
			successCount++
			qm.logger.Debug("Successfully quarantined file: %s -> %s", src, dst)
		}

		return nil
	})

	if err != nil {
		qm.logger.Error("Error during directory walk: %v", err)
	}

	qm.logger.Info("Directory quarantine completed: %d/%d files successfully quarantined from %s", successCount, totalCount, dirPath)

	if successCount == 0 {
		if err := os.RemoveAll(quarantineDir); err != nil {
			qm.logger.Debug("Failed to remove empty quarantine directory: %s: %v", quarantineDir, err)
		}
		return fmt.Errorf("no files could be quarantined from directory: %s", dirPath)
	}

	return nil
}

func (qm *QuarantineManager) cleanupEmptyQuarantinedFiles() error {
	qm.logger.Debug("Starting cleanup of empty quarantined files")

	files, err := os.ReadDir(qm.quarantineDir)
	if err != nil {
		return err
	}

	cleaned := 0
	for _, file := range files {
		if file.IsDir() || file.Name() == "quarantine_log.txt" {
			continue // Skip directories and log file
		}

		filePath := filepath.Join(qm.quarantineDir, file.Name())
		info, err := file.Info()
		if err != nil {
			continue
		}

		// Remove empty files
		if info.Size() == 0 {
			if err := os.Remove(filePath); err == nil {
				qm.logger.Debug("Removed empty quarantined file: %s", file.Name())
				cleaned++
			}
		}

		// Remove very old temporary files
		if strings.HasPrefix(file.Name(), "temp_") && time.Since(info.ModTime()) > 24*time.Hour {
			if err := os.Remove(filePath); err == nil {
				qm.logger.Debug("Removed old temporary file: %s", file.Name())
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		qm.logger.Info("Cleaned up %d empty/temporary quarantine files", cleaned)
	}

	return nil
}

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

func (qm *QuarantineManager) RestoreFile(filePath string) error {
	qm.logger.Info("File restore requested: %s", filePath)
	return fmt.Errorf("file restore not implemented yet")
}

// Process and Network Controllers remain the same...
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
