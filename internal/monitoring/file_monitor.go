// internal/monitoring/file_monitor.go - Critical fixes
package monitoring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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

// Kernel32 procs used for cancellation of overlapped I/O
var (
	kernel32DLL    = windows.NewLazySystemDLL("kernel32.dll")
	procCancelIoEx = kernel32DLL.NewProc("CancelIoEx")
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
	path   string
	handle windows.Handle
	ctx    context.Context
	cancel context.CancelFunc
}

const (
	// Reduced constants to prevent system overload
	SAFE_BUFFER_SIZE  = 512              // Reduced from 1024 for better performance
	MAX_EVENTS        = 10               // Reduced from 20 for better performance
	OPERATION_TIMEOUT = 3 * time.Second  // Reduced from 5 seconds
	MAX_FILE_SIZE     = 25 * 1024 * 1024 // 25MB limit (reduced from 50MB)
)

func NewFileMonitor(cfg *config.FileSystemConfig, logger *utils.Logger, yaraScanner *scanner.YaraScanner) *FileMonitor {
	return &FileMonitor{
		config:           cfg,
		logger:           logger,
		eventChan:        make(chan models.FileEvent, 200), // Reduced from 500 for better performance
		stopChan:         make(chan bool, 1),
		watchers:         make(map[string]*DirectoryWatcher),
		agentID:          "",
		scanner:          yaraScanner,
        maxWorkers:       chooseMaxWorkers(cfg),
		rateLimiter:      make(map[string]time.Time),
		operationTimeout: OPERATION_TIMEOUT,
		maxFileSize:      MAX_FILE_SIZE,
		maxEvents:        MAX_EVENTS,
	}
}

// chooseMaxWorkers picks max workers from config if set (>0), otherwise default to 2
func chooseMaxWorkers(cfg *config.FileSystemConfig) int {
    if cfg != nil && cfg.MaxWorkers > 0 {
        return cfg.MaxWorkers
    }
    return 2
}

func (fm *FileMonitor) Start() error {
	fm.logger.Info("Starting file system monitor with safety limits...")

	// Set agent ID if available
	if fm.agentID == "" {
		fm.logger.Warn("Agent ID not set, some features may be limited")
	}

	// Validate and filter paths more strictly
	validPaths := fm.validateAndFilterPaths(fm.config.Paths)
	if len(validPaths) == 0 {
		fm.logger.Warn("No valid paths found, disabling file monitoring")
		return nil
	}

	// Limit to maximum 5 paths to prevent overload (increased from 2)
	if len(validPaths) > 5 {
		validPaths = validPaths[:5]
		fm.logger.Info("Limited monitoring to first 5 paths to prevent system overload")
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

	// Start rate limiter cleanup worker
	go fm.rateLimiterCleanupWorker()

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
		fm.logger.Debug("Processing path: %s", path)

		expandedPath := expandWindowsEnv(os.ExpandEnv(path))
		fm.logger.Debug("After environment expansion: %s", expandedPath)

		absPath, err := filepath.Abs(expandedPath)
		if err != nil {
			fm.logger.Warn("Invalid path %s: %v", path, err)
			continue
		}
		fm.logger.Debug("Absolute path: %s", absPath)

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
			fm.logger.Debug("Added valid path: %s", absPath)
		}
	}

	fm.logger.Info("Found %d valid paths out of %d configured paths", len(validPaths), len(paths))
	return validPaths
}

// expandWindowsEnv expands Windows-style environment variables like %USERPROFILE% in a path string.
// Go's os.ExpandEnv only supports $VAR or ${VAR}, so we add %VAR% support here.
func expandWindowsEnv(input string) string {
	if input == "" {
		return input
	}

	// First try Go's built-in environment variable expansion for $VAR format
	expanded := os.ExpandEnv(input)

	// Then handle Windows-style %VAR% format
	re := regexp.MustCompile(`%([^%]+)%`)
	out := re.ReplaceAllStringFunc(expanded, func(m string) string {
		// Extract VAR between %...
		match := re.FindStringSubmatch(m)
		if len(match) != 2 {
			return m
		}
		key := match[1]
		if key == "" {
			return m
		}
		val := os.Getenv(key)
		if val == "" {
			// Log warning for missing environment variable
			return m
		}
		return val
	})

	return out
}

func (fm *FileMonitor) watchDirectorySafe(path string) error {
	// Check worker limit
	fm.mu.RLock()
	if fm.workerCount >= fm.maxWorkers {
		fm.mu.RUnlock()
		fm.logger.Warn("Maximum worker limit reached (%d), skipping directory: %s", fm.maxWorkers, path)
		return fmt.Errorf("maximum worker limit reached")
	}
	fm.mu.RUnlock()

	fm.logger.Debug("Attempting to watch directory: %s", path)

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Try to open directory with timeout
	winPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		cancel()
		fm.logger.Error("Failed to convert path to UTF16: %s, error: %v", path, err)
		return fmt.Errorf("failed to convert path: %w", err)
	}

	fm.logger.Debug("Converted path to UTF16: %s", path)

	// Open with OVERLAPPED to allow cancellable, non-blocking I/O
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
		cancel()
		fm.logger.Error("Failed to open directory with CreateFile: %s, error: %v", path, err)
		return fmt.Errorf("failed to open directory: %w", err)
	}

	fm.logger.Debug("Successfully opened directory handle: %s", path)

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

	buffer := make([]byte, SAFE_BUFFER_SIZE)
	var overlapped windows.Overlapped
	var bytesReturned uint32
	// Create event for overlapped I/O (auto-reset)
	hEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		fm.logger.Error("CreateEvent failed: %v", err)
		fm.cleanup(watcher)
		return
	}
	defer windows.CloseHandle(hEvent)
	overlapped.HEvent = hEvent

	pending := false
	for {
		// Stop checks
		select {
		case <-watcher.ctx.Done():
			if pending {
				procCancelIoEx.Call(uintptr(watcher.handle), uintptr(unsafe.Pointer(&overlapped)))
			}
			fm.logger.Debug("Watcher context cancelled: %s", watcher.path)
			return
		case <-fm.stopChan:
			if pending {
				procCancelIoEx.Call(uintptr(watcher.handle), uintptr(unsafe.Pointer(&overlapped)))
			}
			fm.logger.Debug("Global stop signal: %s", watcher.path)
			return
		default:
		}

		// Issue a new overlapped read only if none pending
		if !pending {
			bytesReturned = 0
			err := windows.ReadDirectoryChanges(
				watcher.handle,
				&buffer[0],
				uint32(len(buffer)),
				false,
				windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
				&bytesReturned,
				&overlapped,
				0,
			)
			if err != nil && err != windows.ERROR_IO_PENDING {
				fm.logger.Error("ReadDirectoryChanges failed: %v", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			pending = true
		}

		// Wait for completion with short timeout to remain responsive
		waitRes, err := windows.WaitForSingleObject(hEvent, 500)
		if err != nil {
			fm.logger.Error("WaitForSingleObject failed: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if waitRes == uint32(windows.WAIT_TIMEOUT) {
			// No events yet; loop and check stop signals
			continue
		}

		// Completed: get result
		if ge := windows.GetOverlappedResult(watcher.handle, &overlapped, &bytesReturned, false); ge != nil {
			// If cancelled or error, reset pending and continue
			pending = false
			continue
		}

		if bytesReturned > 0 {
			fm.processDirectoryChangesSafely(watcher.path, buffer[:bytesReturned])
		}
		pending = false
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
		if now.Sub(lastTime) < 500*time.Millisecond { // Increased from 200ms for better performance
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

	// Determine action string once
	actionStr := fm.determineAction(action)

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
				Severity:  "low",
				Category:  "file",
				Source:    "file_monitor",
			},
			FileSize:    0,  // Will be filled if needed
			FileType:    "", // Will be filled if needed
			FileHash:    "", // Will be filled if needed
			Action:      actionStr,
			UserID:      "",
			Permissions: "",
		}

		// Try to get file info if possible
		if fileInfo, err := os.Stat(filePath); err == nil {
			event.FileSize = fileInfo.Size()
		}

		// Send event to channel for agent to receive
		select {
		case fm.eventChan <- event:
			fm.logger.Debug("File event sent to agent: %s %s", actionStr, filePath)
		default:
			fm.logger.Warn("Event channel full, dropping file event: %s", filePath)
		}

		// Run YARA scan for create/modify events
		if action == 0x00000001 || action == 0x00000003 { // FILE_ACTION_ADDED (0x00000001) or FILE_ACTION_MODIFIED (0x00000003)
			go fm.scanFileAndAlert(filePath)
		}
	}()

	// Wait for event processing with timeout
	select {
	case <-done:
		// Event processed successfully
	case <-time.After(fm.operationTimeout):
		fm.logger.Warn("File event processing timeout: %s", filePath)
	}
}

// scanFileAndAlert runs YARA scan and lets the scanner handle alerts/notifications
func (fm *FileMonitor) scanFileAndAlert(filePath string) {
	defer func() {
		if r := recover(); r != nil {
			fm.logger.Error("YARA scan panic: %v", r)
		}
	}()

	if fm.scanner == nil {
		fm.logger.Debug("YARA scanner not available")
		return
	}

	result, err := fm.scanner.ScanFile(filePath)
	if err != nil {
		fm.logger.Debug("YARA scan error: %v", err)
		return
	}

	if result != nil {
		fm.logger.Info("🚨 YARA threat detected in %s: %s (severity: %d)",
			filePath, result.ThreatName, result.Severity)
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

	fm.logger.Info("File monitor event processor started - events will be sent to agent")

	for {
		select {
		case <-fm.stopChan:
			fm.logger.Info("File monitor event processor stopped")
			return
		case <-ticker.C:
			// Periodic cleanup and health check
			fm.cleanupRateLimiter()

			// Log health status
			fm.mu.RLock()
			watcherCount := len(fm.watchers)
			fm.mu.RUnlock()

			if watcherCount > 0 {
				fm.logger.Debug("File monitor health check: %d active watchers", watcherCount)
			}
		}
	}
}

// Start a lightweight worker to periodically cleanup rate limiter (if needed elsewhere)
func (fm *FileMonitor) rateLimiterCleanupWorker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-fm.stopChan:
			return
		case <-ticker.C:
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
