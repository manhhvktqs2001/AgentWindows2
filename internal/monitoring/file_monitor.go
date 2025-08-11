// internal/monitoring/file_monitor.go - Critical fixes to prevent system freeze

package monitoring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/scanner"
	"edr-agent-windows/internal/utils"

	"golang.org/x/sys/windows"
)

type FileMonitor struct {
	config    *config.FileSystemConfig
	logger    *utils.Logger
	eventChan chan models.FileEvent
	stopChan  chan bool
	// handles kept for compatibility; removed to avoid unused warnings
	watchers  map[string]*DirectoryWatcher
	agentID   string
	scanner   *scanner.YaraScanner
	lastAlert map[string]time.Time

	// Critical: Add safety mechanisms
	isShuttingDown bool
	mu             sync.RWMutex
	workerCount    int
	maxWorkers     int
	rateLimiter    map[string]time.Time
	rateMu         sync.Mutex
}

type DirectoryWatcher struct {
	path    string
	handle  windows.Handle
	events  chan models.FileEvent
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	mu      sync.Mutex
}

const (
	FILE_NOTIFY_CHANGE_FILE_NAME   = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME    = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES  = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE        = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE  = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION    = 0x00000040
	FILE_NOTIFY_CHANGE_SECURITY    = 0x00000100

	FILE_ACTION_ADDED            = 0x00000001
	FILE_ACTION_REMOVED          = 0x00000002
	FILE_ACTION_MODIFIED         = 0x00000003
	FILE_ACTION_RENAMED_OLD_NAME = 0x00000004
	FILE_ACTION_RENAMED_NEW_NAME = 0x00000005
)

type FILE_NOTIFY_INFORMATION struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16
}

func NewFileMonitor(cfg *config.FileSystemConfig, logger *utils.Logger, yaraScanner *scanner.YaraScanner) *FileMonitor {
	return &FileMonitor{
		config:      cfg,
		logger:      logger,
		eventChan:   make(chan models.FileEvent, 1000),
		stopChan:    make(chan bool, 1),
		watchers:    make(map[string]*DirectoryWatcher),
		agentID:     "",
		scanner:     yaraScanner,
		lastAlert:   make(map[string]time.Time),
		maxWorkers:  5, // Limit concurrent workers
		rateLimiter: make(map[string]time.Time),
	}
}

func (fm *FileMonitor) Start() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.isShuttingDown {
		return fmt.Errorf("file monitor is shutting down")
	}

	fm.logger.Info("Starting file system monitor...")

	if len(fm.config.Paths) == 0 {
		fm.logger.Warn("No paths configured for monitoring, using safe defaults")
		// Set safe default paths
		fm.config.Paths = []string{
			"C:\\Users\\%USERNAME%\\Downloads",
			"C:\\Users\\%USERNAME%\\Desktop",
		}
	}

	// Validate and filter paths to prevent system locks
	validPaths := fm.validatePaths(fm.config.Paths)
	if len(validPaths) == 0 {
		return fmt.Errorf("no valid paths found for monitoring")
	}

	fm.logger.Info("Validated paths for monitoring: %v", validPaths)

	// Start watching each validated path with limits
	successCount := 0
	for i, path := range validPaths {
		if i >= 3 { // Limit to 3 paths to prevent overload
			fm.logger.Warn("Limiting monitoring to first 3 paths to prevent system overload")
			break
		}

		fm.logger.Debug("Attempting to watch directory: %s", path)
		if err := fm.watchDirectorySafe(path); err != nil {
			fm.logger.Warn("Failed to watch directory %s: %v", path, err)
			continue
		}
		successCount++
		fm.logger.Info("Successfully started watching directory: %s", path)
	}

	if successCount == 0 {
		return fmt.Errorf("failed to start watching any directories")
	}

	// Start event processing with limited workers
	go fm.processEventsSafe()

	fm.logger.Info("File system monitor started successfully - watching %d directories", successCount)
	return nil
}

// validatePaths validates and filters potentially dangerous paths
func (fm *FileMonitor) validatePaths(paths []string) []string {
	var validPaths []string

	// Dangerous paths that should never be monitored
	dangerousPaths := []string{
		"C:\\Windows\\System32",
		"C:\\Windows\\SysWOW64",
		"C:\\Windows\\WinSxS",
		"C:\\Program Files\\Windows Defender",
		"C:\\ProgramData\\Microsoft\\Windows Defender",
		"C:\\Windows\\Temp",
		"C:\\$Recycle.Bin",
		"C:\\System Volume Information",
		"C:\\Recovery",
		"C:\\Boot",
		"C:\\hiberfil.sys",
		"C:\\pagefile.sys",
		"C:\\swapfile.sys",
	}

	for _, path := range paths {
		// Expand environment variables
		expandedPath := os.ExpandEnv(path)

		// Convert to absolute path
		absPath, err := filepath.Abs(expandedPath)
		if err != nil {
			fm.logger.Warn("Invalid path %s: %v", path, err)
			continue
		}

		// Check if path exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			fm.logger.Warn("Path does not exist: %s", absPath)
			continue
		}

		// Check against dangerous paths
		isDangerous := false
		lowerPath := strings.ToLower(absPath)
		for _, dangerous := range dangerousPaths {
			if strings.HasPrefix(lowerPath, strings.ToLower(dangerous)) {
				fm.logger.Warn("Skipping dangerous path: %s", absPath)
				isDangerous = true
				break
			}
		}

		if !isDangerous {
			validPaths = append(validPaths, absPath)
		}
	}

	return validPaths
}

func (fm *FileMonitor) Stop() {
	fm.mu.Lock()
	fm.isShuttingDown = true
	fm.mu.Unlock()

	fm.logger.Info("Stopping file system monitor...")

	// Signal stop to all workers
	select {
	case fm.stopChan <- true:
	default:
		// Channel might be full, that's ok
	}

	// Stop all watchers with timeout
	done := make(chan bool, 1)
	go func() {
		fm.stopAllWatchers()
		done <- true
	}()

	select {
	case <-done:
		fm.logger.Info("All watchers stopped successfully")
	case <-time.After(10 * time.Second):
		fm.logger.Warn("Watcher shutdown timeout, forcing close")
	}

	// Close event channel safely
	select {
	case <-fm.eventChan:
		// Drain any remaining events
	default:
	}
	close(fm.eventChan)

	fm.logger.Info("File system monitor stopped")
}

func (fm *FileMonitor) stopAllWatchers() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for path, watcher := range fm.watchers {
		fm.logger.Debug("Stopping watcher for: %s", path)
		watcher.Stop()
		delete(fm.watchers, path)
	}
}

func (fm *FileMonitor) GetEventChannel() <-chan models.FileEvent {
	return fm.eventChan
}

func (fm *FileMonitor) SetAgentID(agentID string) {
	fm.agentID = agentID
}

func (fm *FileMonitor) SetScanner(scanner *scanner.YaraScanner) {
	fm.scanner = scanner
}

// watchDirectorySafe sets up monitoring with safety checks
func (fm *FileMonitor) watchDirectorySafe(path string) error {
	// Check if already watching
	fm.mu.RLock()
	if _, exists := fm.watchers[path]; exists {
		fm.mu.RUnlock()
		return fmt.Errorf("already watching path: %s", path)
	}
	fm.mu.RUnlock()

	// Check worker limit
	if fm.workerCount >= fm.maxWorkers {
		return fmt.Errorf("maximum worker limit reached")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if directory exists and is accessible
	fileInfo, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", absPath)
	}
	if err != nil {
		return fmt.Errorf("cannot access directory: %w", err)
	}
	if !fileInfo.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	// Convert path to Windows format
	winPath, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return fmt.Errorf("failed to convert path: %w", err)
	}

	// Open directory handle with timeout
	handleChan := make(chan windows.Handle, 1)
	errChan := make(chan error, 1)

	go func() {
		handle, err := windows.CreateFile(
			winPath,
			windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err != nil {
			errChan <- err
			return
		}
		handleChan <- handle
	}()

	var handle windows.Handle
	select {
	case handle = <-handleChan:
		// Success
	case err := <-errChan:
		return fmt.Errorf("failed to open directory: %w", err)
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout opening directory: %s", absPath)
	}

	// Create watcher with context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	watcher := &DirectoryWatcher{
		path:   absPath,
		handle: handle,
		events: make(chan models.FileEvent, 100),
		ctx:    ctx,
		cancel: cancel,
	}

	// Add to watchers map
	fm.mu.Lock()
	fm.watchers[absPath] = watcher
	fm.workerCount++
	fm.mu.Unlock()

	// Start monitoring goroutine
	go fm.monitorDirectorySafe(watcher)

	fm.logger.Info("Started monitoring directory: %s", absPath)
	return nil
}

// monitorDirectorySafe monitors a directory with safety mechanisms
func (fm *FileMonitor) monitorDirectorySafe(watcher *DirectoryWatcher) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("File monitor panic recovered: %v", r)
		}

		// Cleanup
		fm.mu.Lock()
		fm.workerCount--
		fm.mu.Unlock()

		watcher.Stop()
	}()

	fm.logger.Info("Starting directory monitoring for: %s", watcher.path)

	buffer := make([]byte, 4096)
	var overlapped windows.Overlapped
	var bytesReturned uint32

	// Create event for overlapped I/O
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		fm.logger.Error("Failed to create event for directory monitoring: %v", err)
		return
	}
	defer windows.CloseHandle(event)

	overlapped.HEvent = event

	// Monitoring loop with context cancellation
	for {
		select {
		case <-watcher.ctx.Done():
			fm.logger.Info("Stopping directory monitoring for: %s", watcher.path)
			return
		case <-fm.stopChan:
			fm.logger.Info("Global stop signal received for: %s", watcher.path)
			return
		default:
			// Check if shutting down
			fm.mu.RLock()
			if fm.isShuttingDown {
				fm.mu.RUnlock()
				return
			}
			fm.mu.RUnlock()

			// Reset overlapped structure
			overlapped.Internal = 0
			overlapped.InternalHigh = 0
			overlapped.Offset = 0
			overlapped.OffsetHigh = 0

			// Read directory changes with timeout
			err := windows.ReadDirectoryChanges(
				watcher.handle,
				&buffer[0],
				uint32(len(buffer)),
				false, // Don't watch subtree to reduce load
				FILE_NOTIFY_CHANGE_FILE_NAME|
					FILE_NOTIFY_CHANGE_LAST_WRITE|
					FILE_NOTIFY_CHANGE_CREATION,
				&bytesReturned,
				&overlapped,
				0,
			)

			if err != nil {
				if err == windows.ERROR_IO_PENDING {
					// Wait for completion with timeout
					result, err := windows.WaitForSingleObject(event, 3000) // 3 second timeout
					if err != nil {
						fm.logger.Error("Wait for directory changes failed: %v", err)
						time.Sleep(1 * time.Second)
						continue
					}

					if result == uint32(windows.WAIT_TIMEOUT) {
						// Timeout is normal, continue monitoring
						continue
					}

					// Get overlapped result
					err = windows.GetOverlappedResult(watcher.handle, &overlapped, &bytesReturned, false)
					if err != nil {
						fm.logger.Error("Failed to get overlapped result: %v", err)
						time.Sleep(1 * time.Second)
						continue
					}
				} else {
					fm.logger.Error("ReadDirectoryChanges failed: %v", err)
					time.Sleep(2 * time.Second)
					continue
				}
			}

			if bytesReturned > 0 {
				fm.logger.Debug("Directory change detected for: %s (bytes: %d)", watcher.path, bytesReturned)
				fm.processDirectoryChangesSafe(watcher.path, buffer[:bytesReturned])
			}
		}
	}
}

// processDirectoryChangesSafe processes directory change notifications safely
func (fm *FileMonitor) processDirectoryChangesSafe(dirPath string, buffer []byte) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("Directory changes processing panic: %v", r)
		}
	}()

	fm.logger.Debug("Processing directory changes for: %s", dirPath)

	offset := uint32(0)
	processedCount := 0
	maxProcessPerBatch := 50 // Limit processing per batch

	for offset < uint32(len(buffer)) && processedCount < maxProcessPerBatch {
		if offset+uint32(unsafe.Sizeof(FILE_NOTIFY_INFORMATION{})) > uint32(len(buffer)) {
			break
		}

		info := (*FILE_NOTIFY_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		// Validate structure
		if info.FileNameLength == 0 || info.FileNameLength > 1024 {
			break
		}

		// Calculate filename buffer bounds safely
		filenameOffset := offset + uint32(unsafe.Offsetof(info.FileName))
		filenameEnd := filenameOffset + info.FileNameLength

		if filenameEnd > uint32(len(buffer)) {
			break
		}

		// Extract filename safely
		filenameBytes := buffer[filenameOffset:filenameEnd]
		if len(filenameBytes)%2 != 0 {
			break // Invalid UTF-16 length
		}

		// Convert UTF-16 to string
		utf16Slice := make([]uint16, len(filenameBytes)/2)
		for i := 0; i < len(utf16Slice); i++ {
			utf16Slice[i] = uint16(filenameBytes[i*2]) | uint16(filenameBytes[i*2+1])<<8
		}
		filename := windows.UTF16ToString(utf16Slice)

		fullPath := filepath.Join(dirPath, filename)

		fm.logger.Debug("Directory change: %s (action: %d)", fullPath, info.Action)

		// Rate limit processing
		if fm.shouldRateLimit(fullPath) {
			fm.logger.Debug("Rate limiting file event: %s", fullPath)
		} else {
			// Process the event in a separate goroutine to prevent blocking
			go fm.processFileEventSafe(fullPath, info.Action)
		}

		// Move to next entry
		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
		processedCount++
	}
}

// shouldRateLimit checks if we should rate limit processing for this file
func (fm *FileMonitor) shouldRateLimit(filePath string) bool {
	fm.rateMu.Lock()
	defer fm.rateMu.Unlock()

	now := time.Now()
	lastTime, exists := fm.rateLimiter[filePath]

	if exists && now.Sub(lastTime) < 100*time.Millisecond {
		return true
	}

	fm.rateLimiter[filePath] = now

	// Cleanup old entries
	if len(fm.rateLimiter) > 1000 {
		cutoff := now.Add(-1 * time.Minute)
		for path, timestamp := range fm.rateLimiter {
			if timestamp.Before(cutoff) {
				delete(fm.rateLimiter, path)
			}
		}
	}

	return false
}

// processFileEventSafe processes a file event with safety checks
func (fm *FileMonitor) processFileEventSafe(filePath string, action uint32) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("File event processing panic: %v", r)
		}
	}()

	// Check if shutting down
	fm.mu.RLock()
	if fm.isShuttingDown {
		fm.mu.RUnlock()
		return
	}
	fm.mu.RUnlock()

	fm.logger.Debug("Processing file event: %s, action: %d", filePath, action)

	// Skip if file should be excluded
	if fm.shouldExcludeFile(filePath) {
		fm.logger.Debug("File excluded from monitoring: %s", filePath)
		return
	}

	// Get file info with timeout
	var fileInfo os.FileInfo
	var err error

	done := make(chan bool, 1)
	go func() {
		fileInfo, err = os.Stat(filePath)
		done <- true
	}()

	select {
	case <-done:
		if err != nil && !os.IsNotExist(err) {
			fm.logger.Debug("Cannot access file %s: %v", filePath, err)
			return
		}
	case <-time.After(2 * time.Second):
		fm.logger.Debug("File stat timeout: %s", filePath)
		return
	}

	// Create file event
	event := models.FileEvent{
		Event: models.Event{
			ID:        fm.generateEventID(),
			AgentID:   fm.agentID,
			EventType: "file_event",
			Timestamp: time.Now(),
			Severity:  fm.determineSeverity(action, filePath),
			Category:  "file_system",
			Source:    "file_monitor",
			FilePath:  filePath,
		},
		Action: fm.determineAction(action),
	}

	// Add file information if available
	if fileInfo != nil {
		event.FileSize = fileInfo.Size()
		event.FileType = fm.getFileType(filePath)
		event.UserID = fm.getCurrentUser()
	}

	fm.logger.Debug("Created file event: %s - %s", event.Action, filePath)

	// Send event with timeout
	select {
	case fm.eventChan <- event:
		fm.logger.Debug("File event sent to channel: %s - %s", event.Action, filePath)
	case <-time.After(1 * time.Second):
		fm.logger.Warn("Event channel timeout, dropping file event: %s", filePath)
	default:
		fm.logger.Warn("Event channel full, dropping file event: %s", filePath)
	}

	// Scan file with YARA if conditions are met
	if fm.shouldScanFile(action, filePath, fileInfo) {
		go fm.scanFileSafe(filePath, action)
	}
}

// shouldScanFile determines if a file should be scanned
func (fm *FileMonitor) shouldScanFile(action uint32, filePath string, fileInfo os.FileInfo) bool {
	if fm.scanner == nil {
		return false
	}

	// Only scan on create or modify
	if action != FILE_ACTION_ADDED && action != FILE_ACTION_MODIFIED {
		return false
	}

	// Skip if file info is nil
	if fileInfo == nil {
		return false
	}

	// Skip large files
	if fileInfo.Size() > 50*1024*1024 { // 50MB limit
		return false
	}

	// Skip directories
	if fileInfo.IsDir() {
		return false
	}

	return true
}

// scanFileSafe scans a file with YARA safely
func (fm *FileMonitor) scanFileSafe(filePath string, action uint32) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("YARA scan panic: %v", r)
		}
	}()

	// Add timeout to YARA scan
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fm.logger.Error("YARA scan inner panic: %v", r)
			}
			done <- true
		}()

		result, err := fm.scanner.ScanFile(filePath)
		if err != nil {
			fm.logger.Debug("YARA scan failed for %s: %v", filePath, err)
			return
		}

		if result != nil && result.Matched && !result.Suppressed {
			// Apply additional suppression for file monitor context
			if fm.shouldSuppressScan(filePath, result.RuleName) {
				fm.logger.Debug("File monitor suppressed YARA detection: %s -> %s", filePath, result.RuleName)
				return
			}

			// Log detection
			fm.logger.Warn("🚨 FILE MONITOR: YARA threat detected!")
			fm.logger.Warn("File: %s", filePath)
			fm.logger.Warn("Action: %s", fm.determineAction(action))
			fm.logger.Warn("Rule: %s", result.RuleName)
			fm.logger.Warn("Severity: %d", result.Severity)
		}
	}()

	select {
	case <-done:
		// Scan completed
	case <-time.After(10 * time.Second):
		fm.logger.Debug("YARA scan timeout for: %s", filePath)
	}
}

// shouldSuppressScan additional suppression logic for file monitor
func (fm *FileMonitor) shouldSuppressScan(filePath, ruleName string) bool {
	// Check recent alerts
	key := filePath + "|" + ruleName
	if lastTime, exists := fm.lastAlert[key]; exists {
		if time.Since(lastTime) < 2*time.Minute {
			return true
		}
	}
	fm.lastAlert[key] = time.Now()

	// Cleanup old alerts
	if len(fm.lastAlert) > 100 {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, v := range fm.lastAlert {
			if v.Before(cutoff) {
				delete(fm.lastAlert, k)
			}
		}
	}

	return false
}

// Stop method for DirectoryWatcher
func (dw *DirectoryWatcher) Stop() {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	if dw.stopped {
		return
	}

	dw.stopped = true

	if dw.cancel != nil {
		dw.cancel()
	}

	if dw.handle != 0 {
		windows.CloseHandle(dw.handle)
		dw.handle = 0
	}

	if dw.events != nil {
		close(dw.events)
		dw.events = nil
	}
}

// processEventsSafe processes events safely
func (fm *FileMonitor) processEventsSafe() {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("Event processing panic: %v", r)
		}
	}()

	for {
		select {
		case <-fm.stopChan:
			return
		case event, ok := <-fm.eventChan:
			if !ok {
				return
			}
			fm.logger.Debug("Processing file event: %s", event.FilePath)
		case <-time.After(5 * time.Second):
			// Periodic check to prevent hanging
			continue
		}
	}
}

// Helper methods remain the same but with additional safety checks
func (fm *FileMonitor) shouldExcludeFile(filePath string) bool {
	// Enhanced exclusion logic
	if filePath == "" {
		return true
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	excludeExts := []string{
		".tmp", ".log", ".bak", ".cache", ".db", ".sqlite",
		".etl", ".evtx", ".lock", ".crdownload", ".partial",
	}

	for _, excludeExt := range excludeExts {
		if ext == excludeExt {
			return true
		}
	}

	// Additional exclusions specific to preventing system issues
	lower := strings.ToLower(filePath)
	dangerousPatterns := []string{
		"\\windows\\system32\\",
		"\\windows\\syswow64\\",
		"\\windows\\winsxs\\",
		"\\programdata\\microsoft\\windows defender\\",
		"\\$recycle.bin\\",
		"\\system volume information\\",
		"\\recovery\\",
		"\\windows\\temp\\",
		"\\appdata\\local\\temp\\",
		"\\quarantine\\",
		"\\yara-rules\\",
		"\\edr-agent",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// Other helper methods with safety improvements
func (fm *FileMonitor) determineAction(action uint32) string {
	switch action {
	case FILE_ACTION_ADDED:
		return "create"
	case FILE_ACTION_REMOVED:
		return "delete"
	case FILE_ACTION_MODIFIED:
		return "modify"
	case FILE_ACTION_RENAMED_OLD_NAME:
		return "rename_old"
	case FILE_ACTION_RENAMED_NEW_NAME:
		return "rename_new"
	default:
		return "unknown"
	}
}

func (fm *FileMonitor) determineSeverity(action uint32, filePath string) string {
	if fm.isExecutable(filePath) {
		return "high"
	}
	if fm.isSystemFile(filePath) {
		return "medium"
	}
	return "low"
}

func (fm *FileMonitor) isExecutable(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	executableExts := []string{".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".com", ".pif"}
	for _, execExt := range executableExts {
		if ext == execExt {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) isSystemFile(filePath string) bool {
	systemPaths := []string{"\\Windows\\", "\\Program Files\\", "\\Program Files (x86)\\"}
	filePathLower := strings.ToLower(filePath)
	for _, sysPath := range systemPaths {
		if strings.Contains(filePathLower, strings.ToLower(sysPath)) {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) getFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".exe", ".dll", ".sys":
		return "executable"
	case ".txt", ".log", ".ini", ".cfg":
		return "text"
	case ".doc", ".docx", ".pdf":
		return "document"
	case ".jpg", ".jpeg", ".png", ".gif":
		return "image"
	case ".mp3", ".wav", ".avi", ".mp4":
		return "media"
	default:
		return "unknown"
	}
}

func (fm *FileMonitor) getCurrentUser() string {
	return "current_user" // Simplified implementation
}

func (fm *FileMonitor) generateEventID() string {
	return fmt.Sprintf("file_%d", time.Now().UnixNano())
}
