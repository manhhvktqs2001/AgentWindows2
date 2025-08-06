package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/scanner"
	"edr-agent-windows/internal/utils"

	"golang.org/x/sys/windows"
)

type FileMonitor struct {
	config      config.FileMonitorConfig
	logger      *utils.Logger
	scanner     *scanner.YaraScanner
	directories map[string]*DirectoryWatch
	stopChan    chan bool
}

type DirectoryWatch struct {
	handle     windows.Handle
	buffer     []byte
	overlapped *windows.Overlapped
	path       string
}

type FileEvent struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	FilePath  string    `json:"file_path"`
	FileName  string    `json:"file_name"`
	Action    string    `json:"action"`
	FileSize  int64     `json:"file_size"`
	Hash      string    `json:"hash"`
	Platform  string    `json:"platform"`
}

func NewFileMonitor(config config.FileMonitorConfig, logger *utils.Logger, scanner *scanner.YaraScanner) *FileMonitor {
	return &FileMonitor{
		config:      config,
		logger:      logger,
		scanner:     scanner,
		directories: make(map[string]*DirectoryWatch),
		stopChan:    make(chan bool),
	}
}

func (fm *FileMonitor) Start() error {
	fm.logger.Info("Starting Windows file monitor...")

	for _, path := range fm.config.Paths {
		err := fm.watchDirectory(path)
		if err != nil {
			fm.logger.Error("Failed to watch directory %s: %v", path, err)
			continue
		}
		fm.logger.Info("Watching directory: %s", path)
	}

	return nil
}

func (fm *FileMonitor) Stop() {
	fm.logger.Info("Stopping Windows file monitor...")
	close(fm.stopChan)

	for _, watch := range fm.directories {
		windows.CloseHandle(watch.handle)
	}
}

func (fm *FileMonitor) watchDirectory(path string) error {
	// Convert path to UTF16
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	// Open directory handle
	handle, err := windows.CreateFile(
		pathUTF16,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return err
	}

	// Create directory watch
	watch := &DirectoryWatch{
		handle: handle,
		buffer: make([]byte, 64*1024), // 64KB buffer
		path:   path,
	}

	fm.directories[path] = watch
	go fm.monitorDirectory(watch)

	return nil
}

func (fm *FileMonitor) monitorDirectory(watch *DirectoryWatch) {
	for {
		select {
		case <-fm.stopChan:
			return
		default:
			var bytesReturned uint32
			err := windows.ReadDirectoryChanges(
				watch.handle,
				&watch.buffer[0],
				uint32(len(watch.buffer)),
				fm.config.Recursive,
				windows.FILE_NOTIFY_CHANGE_FILE_NAME|
					windows.FILE_NOTIFY_CHANGE_DIR_NAME|
					windows.FILE_NOTIFY_CHANGE_SIZE|
					windows.FILE_NOTIFY_CHANGE_LAST_WRITE,
				&bytesReturned,
				watch.overlapped,
				0,
			)

			if err != nil {
				fm.logger.Error("ReadDirectoryChanges failed: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			fm.parseNotifications(watch.buffer[:bytesReturned], watch.path)
		}
	}
}

func (fm *FileMonitor) parseNotifications(buffer []byte, basePath string) {
	offset := 0

	for offset < len(buffer) {
		// Parse FILE_NOTIFY_INFORMATION structure
		nextEntryOffset := *(*uint32)(unsafe.Pointer(&buffer[offset]))
		action := *(*uint32)(unsafe.Pointer(&buffer[offset+4]))
		fileNameLength := *(*uint32)(unsafe.Pointer(&buffer[offset+8]))

		// Extract filename (UTF-16)
		filenameBytes := buffer[offset+12 : offset+12+int(fileNameLength)]
		filename := windows.UTF16ToString((*(*[]uint16)(unsafe.Pointer(&filenameBytes)))[:fileNameLength/2])

		fullPath := filepath.Join(basePath, filename)

		// Create file event
		event := &FileEvent{
			AgentID:   "agent-id", // TODO: Get from config
			Timestamp: time.Now(),
			EventType: "file",
			FilePath:  fullPath,
			FileName:  filename,
			Action:    fm.actionToString(action),
			Platform:  "windows",
		}

		// Get file info
		if stat, err := os.Stat(fullPath); err == nil {
			event.FileSize = stat.Size()
		}

		// Calculate hash if needed
		if fm.shouldCalculateHash(event) {
			event.Hash = fm.calculateFileHash(fullPath)
		}

		// YARA scan if enabled
		if fm.config.ScanOnWrite && event.Action == "created" {
			go fm.scanFile(fullPath)
		}

		// TODO: Send event to agent
		fm.logger.Debug("File event: %s %s", event.Action, event.FilePath)

		if nextEntryOffset == 0 {
			break
		}
		offset += int(nextEntryOffset)
	}
}

func (fm *FileMonitor) actionToString(action uint32) string {
	switch action {
	case windows.FILE_ACTION_ADDED:
		return "created"
	case windows.FILE_ACTION_REMOVED:
		return "deleted"
	case windows.FILE_ACTION_MODIFIED:
		return "modified"
	case windows.FILE_ACTION_RENAMED_OLD_NAME:
		return "renamed_old"
	case windows.FILE_ACTION_RENAMED_NEW_NAME:
		return "renamed_new"
	default:
		return "unknown"
	}
}

func (fm *FileMonitor) shouldCalculateHash(event *FileEvent) bool {
	// Only calculate hash for executable files
	ext := strings.ToLower(filepath.Ext(event.FileName))
	return ext == ".exe" || ext == ".dll" || ext == ".sys"
}

func (fm *FileMonitor) calculateFileHash(filePath string) string {
	// TODO: Implement file hash calculation
	return ""
}

func (fm *FileMonitor) scanFile(filePath string) {
	if fm.scanner != nil {
		result, err := fm.scanner.ScanFile(filePath)
		if err != nil {
			fm.logger.Error("YARA scan failed for %s: %v", filePath, err)
			return
		}

		if result.Matched {
			fm.logger.Warn("YARA rule matched for %s: %s", filePath, result.RuleName)
			// TODO: Create alert
		}
	}
}
