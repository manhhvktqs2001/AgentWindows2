package monitoring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	handles   []windows.Handle
	watchers  map[string]*DirectoryWatcher
	agentID   string               // Add agent ID field
	scanner   *scanner.YaraScanner // Add YARA scanner
}

type DirectoryWatcher struct {
	path   string
	handle windows.Handle
	events chan models.FileEvent
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

func NewFileMonitor(cfg *config.FileSystemConfig, logger *utils.Logger) *FileMonitor {
	return &FileMonitor{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.FileEvent, 1000),
		stopChan:  make(chan bool),
		watchers:  make(map[string]*DirectoryWatcher),
		agentID:   "",  // Will be set later
		scanner:   nil, // Will be set later
	}
}

// Start begins file system monitoring
func (fm *FileMonitor) Start() error {
	fm.logger.Info("Starting file system monitor...")

	// Validate paths
	if len(fm.config.Paths) == 0 {
		return fmt.Errorf("no paths configured for monitoring")
	}

	// Start watching each configured path
	for _, path := range fm.config.Paths {
		if err := fm.watchDirectory(path); err != nil {
			fm.logger.Warn("Failed to watch directory %s: %v", path, err)
			continue
		}
	}

	// Start event processing goroutine
	go fm.processEvents()

	fm.logger.Info("File system monitor started successfully")
	return nil
}

// Stop stops file system monitoring
func (fm *FileMonitor) Stop() {
	fm.logger.Info("Stopping file system monitor...")

	// Signal stop
	close(fm.stopChan)

	// Close all watchers
	for _, watcher := range fm.watchers {
		windows.CloseHandle(watcher.handle)
	}

	// Close event channel
	close(fm.eventChan)

	fm.logger.Info("File system monitor stopped")
}

// GetEventChannel returns the channel for file events
func (fm *FileMonitor) GetEventChannel() <-chan models.FileEvent {
	return fm.eventChan
}

// SetAgentID sets the agent ID for events
func (fm *FileMonitor) SetAgentID(agentID string) {
	fm.agentID = agentID
}

// SetScanner sets the YARA scanner
func (fm *FileMonitor) SetScanner(scanner *scanner.YaraScanner) {
	fm.scanner = scanner
}

// watchDirectory sets up monitoring for a specific directory
func (fm *FileMonitor) watchDirectory(path string) error {
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", absPath)
	}

	// Convert path to Windows format
	winPath, err := windows.UTF16PtrFromString(absPath)
	if err != nil {
		return fmt.Errorf("failed to convert path: %w", err)
	}

	// Open directory handle
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
		return fmt.Errorf("failed to open directory: %w", err)
	}

	// Create watcher
	watcher := &DirectoryWatcher{
		path:   absPath,
		handle: handle,
		events: make(chan models.FileEvent, 100),
	}

	fm.watchers[absPath] = watcher

	// Start monitoring goroutine
	go fm.monitorDirectory(watcher)

	fm.logger.Info("Started monitoring directory: %s", absPath)
	return nil
}

// monitorDirectory monitors a single directory for changes
func (fm *FileMonitor) monitorDirectory(watcher *DirectoryWatcher) {
	buffer := make([]byte, 4096)
	var overlapped windows.Overlapped
	var bytesReturned uint32

	for {
		select {
		case <-fm.stopChan:
			return
		default:
			// Read directory changes using Windows API
			err := windows.ReadDirectoryChanges(
				watcher.handle,
				&buffer[0],
				uint32(len(buffer)),
				true, // Watch subtree
				FILE_NOTIFY_CHANGE_FILE_NAME|
					FILE_NOTIFY_CHANGE_DIR_NAME|
					FILE_NOTIFY_CHANGE_ATTRIBUTES|
					FILE_NOTIFY_CHANGE_SIZE|
					FILE_NOTIFY_CHANGE_LAST_WRITE|
					FILE_NOTIFY_CHANGE_LAST_ACCESS|
					FILE_NOTIFY_CHANGE_CREATION|
					FILE_NOTIFY_CHANGE_SECURITY,
				&bytesReturned,
				&overlapped,
				0, // No completion routine
			)

			if err != nil {
				fm.logger.Error("Failed to read directory changes: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Wait for completion
			err = windows.GetOverlappedResult(watcher.handle, &overlapped, &bytesReturned, true)
			if err != nil {
				fm.logger.Error("Failed to get overlapped result: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Process the changes
			fm.processDirectoryChanges(watcher.path, buffer[:bytesReturned])
		}
	}
}

// processDirectoryChanges processes directory change notifications
func (fm *FileMonitor) processDirectoryChanges(dirPath string, buffer []byte) {
	offset := uint32(0)

	for offset < uint32(len(buffer)) {
		info := (*FILE_NOTIFY_INFORMATION)(unsafe.Pointer(&buffer[offset]))

		// Extract filename
		filename := windows.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&info.FileName[0]))[:info.FileNameLength/2])
		fullPath := filepath.Join(dirPath, filename)

		// Process the event
		fm.processFileEvent(fullPath, info.Action)

		// Move to next entry
		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
	}
}

// processFileEvent processes a single file event
func (fm *FileMonitor) processFileEvent(filePath string, action uint32) {
	// Skip if file should be excluded
	if fm.shouldExcludeFile(filePath) {
		return
	}

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		// File might have been deleted
		fileInfo = nil
	}

	// Create file event
	event := models.FileEvent{
		Event: models.Event{
			ID:        fm.generateEventID(),
			AgentID:   fm.agentID, // Set agent ID
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
		event.FileHash = fm.calculateFileHash(filePath)
		event.Permissions = fm.getFilePermissions(fileInfo)
		event.UserID = fm.getCurrentUser()
	}

	// Send event
	select {
	case fm.eventChan <- event:
		fm.logger.Debug("File event: %s - %s", event.Action, filePath)
	default:
		fm.logger.Warn("Event channel full, dropping file event")
	}

	// Scan file with YARA if scanner is available and file is created/modified
	if fm.scanner != nil && (action == FILE_ACTION_ADDED || action == FILE_ACTION_MODIFIED) {
		if fileInfo != nil {
			go func() {
				result, err := fm.scanner.ScanFile(filePath)
				if err != nil {
					fm.logger.Error("YARA scan failed for %s: %v", filePath, err)
					return
				}
				if result != nil && result.Matched {
					// Print alert directly to terminal
					fmt.Printf("\n🔍 FILE MONITOR: YARA threat detected!\n")
					fmt.Printf("File: %s\n", filePath)
					fmt.Printf("Action: %s\n", fm.determineAction(action))
					fmt.Printf("Rule: %s\n", result.RuleName)
					fmt.Printf("Severity: %d\n", result.Severity)
					fmt.Printf("🔍 END FILE MONITOR ALERT\n\n")

					fm.logger.Warn("YARA threat detected: %s -> %s", filePath, result.RuleName)
				}
			}()
		}
	}
}

// shouldExcludeFile checks if a file should be excluded from monitoring
func (fm *FileMonitor) shouldExcludeFile(filePath string) bool {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, excludeExt := range fm.config.ExcludeExtensions {
		if strings.EqualFold(ext, excludeExt) {
			return true
		}
	}

	// Check file size
	if fileInfo, err := os.Stat(filePath); err == nil {
		maxSize := fm.parseFileSize(fm.config.MaxFileSize)
		if maxSize > 0 && fileInfo.Size() > maxSize {
			return true
		}
	}

	// Skip temporary files
	if strings.Contains(strings.ToLower(filePath), "temp") ||
		strings.Contains(strings.ToLower(filePath), "tmp") {
		return true
	}

	return false
}

// determineAction determines the file action from Windows notification
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

// determineSeverity determines event severity based on action and file type
func (fm *FileMonitor) determineSeverity(action uint32, filePath string) string {
	// High severity for executable files
	if fm.isExecutable(filePath) {
		return "high"
	}

	// Medium severity for system files
	if fm.isSystemFile(filePath) {
		return "medium"
	}

	// Low severity for other files
	return "low"
}

// isExecutable checks if a file is executable
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

// isSystemFile checks if a file is a system file
func (fm *FileMonitor) isSystemFile(filePath string) bool {
	systemPaths := []string{
		"\\Windows\\",
		"\\Program Files\\",
		"\\Program Files (x86)\\",
	}

	filePathLower := strings.ToLower(filePath)
	for _, sysPath := range systemPaths {
		if strings.Contains(filePathLower, strings.ToLower(sysPath)) {
			return true
		}
	}

	return false
}

// getFileType determines the file type
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

// calculateFileHash calculates SHA256 hash of file
func (fm *FileMonitor) calculateFileHash(filePath string) string {
	// For performance, only calculate hash for small files or executables
	if fm.isExecutable(filePath) {
		// Implementation would calculate SHA256 hash
		return "hash_placeholder"
	}
	return ""
}

// getFilePermissions gets file permissions as string
func (fm *FileMonitor) getFilePermissions(fileInfo os.FileInfo) string {
	// Implementation would extract Windows file permissions
	return "rw-r--r--"
}

// getCurrentUser gets current user ID
func (fm *FileMonitor) getCurrentUser() string {
	// Implementation would get current user
	return "current_user"
}

// parseFileSize parses file size string to bytes
func (fm *FileMonitor) parseFileSize(sizeStr string) int64 {
	// Implementation would parse size strings like "100MB", "1GB"
	return 100 * 1024 * 1024 // Default 100MB
}

// generateEventID generates unique event ID
func (fm *FileMonitor) generateEventID() string {
	return fmt.Sprintf("file_%d", time.Now().UnixNano())
}

// processEvents processes events from all watchers
func (fm *FileMonitor) processEvents() {
	for {
		select {
		case <-fm.stopChan:
			return
		case event := <-fm.eventChan:
			// Process event (e.g., send to scanner, log, etc.)
			fm.logger.Debug("Processing file event: %s", event.FilePath)
		}
	}
}
