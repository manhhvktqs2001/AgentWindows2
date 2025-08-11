// internal/monitoring/file_monitor.go - Critical fixes
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
	watchers  map[string]*DirectoryWatcher
	agentID   string
	scanner   *scanner.YaraScanner

	// Critical: Add safety mechanisms
	isShuttingDown bool
	mu             sync.RWMutex
	workerCount    int
	maxWorkers     int
	rateLimiter    map[string]time.Time
	rateMu         sync.Mutex

	// Add timeout handling
	operationTimeout time.Duration
	maxFileSize      int64
	maxEvents        int
}

type DirectoryWatcher struct {
	path    string
	handle  windows.Handle
	ctx     context.Context
	cancel  context.CancelFunc
	stopped bool
	mu      sync.Mutex
}

const (
	// Reduced constants to prevent system overload
	SAFE_BUFFER_SIZE  = 1024 // Reduced from 4096
	MAX_EVENTS        = 20   // Limit events per batch
	OPERATION_TIMEOUT = 5 * time.Second
	MAX_FILE_SIZE     = 50 * 1024 * 1024 // 50MB limit
)

func NewFileMonitor(cfg *config.FileSystemConfig, logger *utils.Logger, yaraScanner *scanner.YaraScanner) *FileMonitor {
	return &FileMonitor{
		config:           cfg,
		logger:           logger,
		eventChan:        make(chan models.FileEvent, 500), // Reduced buffer
		stopChan:         make(chan bool, 1),
		watchers:         make(map[string]*DirectoryWatcher),
		agentID:          "",
		scanner:          yaraScanner,
		maxWorkers:       3, // Reduced from 5
		rateLimiter:      make(map[string]time.Time),
		operationTimeout: OPERATION_TIMEOUT,
		maxFileSize:      MAX_FILE_SIZE,
		maxEvents:        MAX_EVENTS,
	}
}

func (fm *FileMonitor) Start() error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if fm.isShuttingDown {
		return fmt.Errorf("file monitor is shutting down")
	}

	fm.logger.Info("Starting file system monitor with safety limits...")

	// CRITICAL: Skip monitoring if no paths or disable by default
	if len(fm.config.Paths) == 0 || !fm.config.Enabled {
		fm.logger.Info("File monitoring disabled or no paths configured")
		return nil
	}

	// Validate and filter paths more strictly
	validPaths := fm.validateAndFilterPaths(fm.config.Paths)
	if len(validPaths) == 0 {
		fm.logger.Warn("No valid paths found, disabling file monitoring")
		return nil
	}

	// Limit to maximum 2 paths to prevent overload
	if len(validPaths) > 2 {
		validPaths = validPaths[:2]
		fm.logger.Warn("Limited monitoring to first 2 paths to prevent system overload")
	}

	// Start watching each validated path with strict limits
	successCount := 0
	for _, path := range validPaths {
		if err := fm.watchDirectorySafe(path); err != nil {
			fm.logger.Warn("Failed to watch directory %s: %v", path, err)
			continue
		}
		successCount++
	}

	if successCount == 0 {
		fm.logger.Warn("Failed to start watching any directories, continuing without file monitoring")
		return nil // Don't fail, just disable file monitoring
	}

	// Start event processing with strict limits
	go fm.processEventsWithLimits()

	fm.logger.Info("File system monitor started successfully - watching %d directories", successCount)
	return nil
}

func (fm *FileMonitor) validateAndFilterPaths(paths []string) []string {
	var validPaths []string

	// More restrictive dangerous paths
	dangerousPaths := []string{
		"C:\\Windows\\System32",
		"C:\\Windows\\SysWOW64",
		"C:\\Windows\\WinSxS",
		"C:\\Windows",
		"C:\\Program Files\\Windows Defender",
		"C:\\ProgramData\\Microsoft\\Windows Defender",
		"C:\\$Recycle.Bin",
		"C:\\System Volume Information",
		"C:\\Recovery",
		"C:\\Boot",
		"C:\\hiberfil.sys",
		"C:\\pagefile.sys",
		"C:\\swapfile.sys",
		"C:\\Windows\\Temp",
		"C:\\temp\\go-build", // Exclude Go build temp
	}

	for _, path := range paths {
		expandedPath := os.ExpandEnv(path)
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

		// More strict dangerous path checking
		isDangerous := false
		lowerPath := strings.ToLower(absPath)
		for _, dangerous := range dangerousPaths {
			if strings.HasPrefix(lowerPath, strings.ToLower(dangerous)) {
				fm.logger.Warn("Skipping dangerous system path: %s", absPath)
				isDangerous = true
				break
			}
		}

		// Skip development paths that could cause infinite loops
		if strings.Contains(lowerPath, "\\agentwindows\\") ||
			strings.Contains(lowerPath, "\\go\\src\\") ||
			strings.Contains(lowerPath, "\\go-build") {
			fm.logger.Warn("Skipping development path: %s", absPath)
			continue
		}

		if !isDangerous {
			validPaths = append(validPaths, absPath)
		}
	}

	return validPaths
}

func (fm *FileMonitor) watchDirectorySafe(path string) error {
	// Check worker limit
	fm.mu.RLock()
	if fm.workerCount >= fm.maxWorkers {
		fm.mu.RUnlock()
		return fmt.Errorf("maximum worker limit reached")
	}
	fm.mu.RUnlock()

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Try to open directory with timeout
	winPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to convert path: %w", err)
	}

	// Open with minimal flags to reduce system impact
	handle, err := windows.CreateFile(
		winPath,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, // Remove OVERLAPPED to simplify
		0,
	)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to open directory: %w", err)
	}

	watcher := &DirectoryWatcher{
		path:   path,
		handle: handle,
		ctx:    ctx,
		cancel: cancel,
	}

	fm.mu.Lock()
	fm.watchers[path] = watcher
	fm.workerCount++
	fm.mu.Unlock()

	// Start monitoring with strict limits
	go fm.monitorDirectoryWithLimits(watcher)

	fm.logger.Info("Started monitoring directory: %s", path)
	return nil
}

func (fm *FileMonitor) monitorDirectoryWithLimits(watcher *DirectoryWatcher) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("File monitor panic recovered: %v", r)
		}
		fm.cleanup(watcher)
	}()

	buffer := make([]byte, SAFE_BUFFER_SIZE) // Smaller buffer
	eventCount := 0
	maxEvents := fm.maxEvents

	for {
		select {
		case <-watcher.ctx.Done():
			fm.logger.Debug("Watcher context cancelled: %s", watcher.path)
			return
		case <-fm.stopChan:
			fm.logger.Debug("Global stop signal: %s", watcher.path)
			return
		default:
			// Check if shutting down
			fm.mu.RLock()
			if fm.isShuttingDown {
				fm.mu.RUnlock()
				return
			}
			fm.mu.RUnlock()

			// Limit events per cycle
			if eventCount >= maxEvents {
				fm.logger.Debug("Event limit reached, sleeping: %s", watcher.path)
				time.Sleep(1 * time.Second)
				eventCount = 0
				continue
			}

			var bytesReturned uint32

			// Simple synchronous read with timeout
			done := make(chan error, 1)
			go func() {
				err := windows.ReadDirectoryChanges(
					watcher.handle,
					&buffer[0],
					uint32(len(buffer)),
					false, // Don't watch subtree
					windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
					&bytesReturned,
					nil, // No overlapped
					0,
				)
				done <- err
			}()

			select {
			case err := <-done:
				if err != nil {
					fm.logger.Error("ReadDirectoryChanges failed: %v", err)
					time.Sleep(2 * time.Second)
					continue
				}

				if bytesReturned > 0 {
					fm.processDirectoryChangesSafely(watcher.path, buffer[:bytesReturned])
					eventCount++
				}

			case <-time.After(fm.operationTimeout):
				fm.logger.Debug("Directory monitoring timeout: %s", watcher.path)
				continue

			case <-watcher.ctx.Done():
				return
			}
		}
	}
}

func (fm *FileMonitor) processDirectoryChangesSafely(dirPath string, buffer []byte) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("Directory changes processing panic: %v", r)
		}
	}()

	// Process with strict limits
	offset := uint32(0)
	processedCount := 0
	maxProcessPerBatch := 10 // Reduced limit

	for offset < uint32(len(buffer)) && processedCount < maxProcessPerBatch {
		// Validate buffer bounds more strictly
		if offset+12 > uint32(len(buffer)) { // Minimum structure size
			break
		}

		info := (*FILE_NOTIFY_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		if info.FileNameLength == 0 || info.FileNameLength > 1024 {
			break
		}

		// Calculate and validate filename bounds
		filenameOffset := offset + 12 // Size of structure before filename
		filenameEnd := filenameOffset + info.FileNameLength

		if filenameEnd > uint32(len(buffer)) {
			break
		}

		// Extract filename safely
		filenameBytes := buffer[filenameOffset:filenameEnd]
		if len(filenameBytes)%2 != 0 {
			break
		}

		// Convert UTF-16 to string
		utf16Slice := make([]uint16, len(filenameBytes)/2)
		for i := 0; i < len(utf16Slice); i++ {
			utf16Slice[i] = uint16(filenameBytes[i*2]) | uint16(filenameBytes[i*2+1])<<8
		}
		filename := windows.UTF16ToString(utf16Slice)

		fullPath := filepath.Join(dirPath, filename)

		// Enhanced rate limiting and filtering
		if fm.shouldProcessFile(fullPath) {
			go fm.processFileEventSafely(fullPath, info.Action)
		}

		// Move to next entry
		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
		processedCount++
	}
}

func (fm *FileMonitor) shouldProcessFile(filePath string) bool {
	// Rate limiting
	fm.rateMu.Lock()
	defer fm.rateMu.Unlock()

	now := time.Now()
	if lastTime, exists := fm.rateLimiter[filePath]; exists {
		if now.Sub(lastTime) < 200*time.Millisecond { // Increased rate limit
			return false
		}
	}
	fm.rateLimiter[filePath] = now

	// Enhanced exclusion
	if fm.shouldExcludeFile(filePath) {
		return false
	}

	// Check file size before processing
	if fileInfo, err := os.Stat(filePath); err == nil {
		if fileInfo.Size() > fm.maxFileSize {
			return false
		}
		if fileInfo.IsDir() {
			return false
		}
	}

	return true
}

func (fm *FileMonitor) processFileEventSafely(filePath string, action uint32) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("File event processing panic: %v", r)
		}
	}()

	// Quick exit checks
	fm.mu.RLock()
	if fm.isShuttingDown {
		fm.mu.RUnlock()
		return
	}
	fm.mu.RUnlock()

	// Create event with timeout
	done := make(chan bool, 1)
	go func() {
		defer func() { done <- true }()

		event := models.FileEvent{
			Event: models.Event{
				ID:        fm.generateEventID(),
				AgentID:   fm.agentID,
				EventType: "file_event",
				Timestamp: time.Now(),
				Severity:  "low", // Default to low
				Category:  "file_system",
				Source:    "file_monitor",
				FilePath:  filePath,
			},
			Action: fm.determineAction(action),
		}

		// Send with timeout
		select {
		case fm.eventChan <- event:
			fm.logger.Debug("File event sent: %s", filePath)
		case <-time.After(500 * time.Millisecond):
			fm.logger.Debug("Event send timeout: %s", filePath)
		}
	}()

	select {
	case <-done:
		// Completed
	case <-time.After(2 * time.Second):
		fm.logger.Debug("File processing timeout: %s", filePath)
	}
}

func (fm *FileMonitor) processEventsWithLimits() {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("Event processing panic: %v", r)
		}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopChan:
			return
		case event, ok := <-fm.eventChan:
			if !ok {
				return
			}
			fm.logger.Debug("Processing file event: %s", event.FilePath)
		case <-ticker.C:
			// Periodic cleanup
			fm.cleanupRateLimiter()
		}
	}
}

func (fm *FileMonitor) cleanupRateLimiter() {
	fm.rateMu.Lock()
	defer fm.rateMu.Unlock()

	if len(fm.rateLimiter) > 500 {
		cutoff := time.Now().Add(-5 * time.Minute)
		for path, timestamp := range fm.rateLimiter {
			if timestamp.Before(cutoff) {
				delete(fm.rateLimiter, path)
			}
		}
	}
}

func (fm *FileMonitor) cleanup(watcher *DirectoryWatcher) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if watcher.cancel != nil {
		watcher.cancel()
	}
	if watcher.handle != 0 {
		windows.CloseHandle(watcher.handle)
		watcher.handle = 0
	}

	delete(fm.watchers, watcher.path)
	fm.workerCount--
}

func (fm *FileMonitor) Stop() {
	fm.mu.Lock()
	fm.isShuttingDown = true
	fm.mu.Unlock()

	fm.logger.Info("Stopping file system monitor...")

	// Signal stop with timeout
	select {
	case fm.stopChan <- true:
	case <-time.After(1 * time.Second):
		fm.logger.Warn("Stop signal timeout")
	}

	// Cleanup all watchers with timeout
	done := make(chan bool, 1)
	go func() {
		fm.stopAllWatchers()
		done <- true
	}()

	select {
	case <-done:
		fm.logger.Info("All watchers stopped")
	case <-time.After(10 * time.Second):
		fm.logger.Warn("Watcher cleanup timeout")
	}

	close(fm.eventChan)
	fm.logger.Info("File system monitor stopped")
}

func (fm *FileMonitor) stopAllWatchers() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	for path, watcher := range fm.watchers {
		fm.logger.Debug("Stopping watcher: %s", path)
		if watcher.cancel != nil {
			watcher.cancel()
		}
		if watcher.handle != 0 {
			windows.CloseHandle(watcher.handle)
		}
		delete(fm.watchers, path)
	}
}

// Helper methods
func (fm *FileMonitor) shouldExcludeFile(filePath string) bool {
	if filePath == "" {
		return true
	}

	lower := strings.ToLower(filePath)

	// Exclude development and system files
	excludePatterns := []string{
		"\\windows\\system32\\", "\\windows\\syswow64\\",
		"\\programdata\\microsoft\\windows defender\\",
		"\\$recycle.bin\\", "\\system volume information\\",
		"\\recovery\\", "\\windows\\temp\\", "\\temp\\go-build",
		"\\agentwindows\\", "\\.git\\", "\\quarantine\\",
		".tmp", ".log", ".bak", ".cache", ".lock",
		".etl", ".evtx", ".crdownload", ".partial",
	}

	for _, pattern := range excludePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// Rest of helper methods remain simple and safe
func (fm *FileMonitor) SetAgentID(agentID string) {
	fm.agentID = agentID
}

func (fm *FileMonitor) GetEventChannel() <-chan models.FileEvent {
	return fm.eventChan
}

func (fm *FileMonitor) determineAction(action uint32) string {
	switch action {
	case 0x00000001:
		return "create"
	case 0x00000002:
		return "delete"
	case 0x00000003:
		return "modify"
	default:
		return "unknown"
	}
}

func (fm *FileMonitor) generateEventID() string {
	return fmt.Sprintf("file_%d", time.Now().UnixNano())
}

type FILE_NOTIFY_INFORMATION struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16
}
