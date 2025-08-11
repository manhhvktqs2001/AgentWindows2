package monitoring

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"

	"sync"

	"golang.org/x/sys/windows"
)

type RegistryMonitor struct {
	config     *config.RegistryConfig
	logger     *utils.Logger
	eventChan  chan models.RegistryEvent
	stopChan   chan bool
	agentID    string
	watchers   map[string]*RegistryWatcher
	isStopping bool
	mu         sync.RWMutex
}

type RegistryWatcher struct {
	keyPath string
	handle  windows.Handle
	events  chan models.RegistryEvent
}

const (
	HKEY_LOCAL_MACHINE = 0x80000002
	HKEY_CURRENT_USER  = 0x80000001
	HKEY_USERS         = 0x80000003
	HKEY_CLASSES_ROOT  = 0x80000000

	REG_NOTIFY_CHANGE_NAME       = 0x00000001
	REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002
	REG_NOTIFY_CHANGE_LAST_SET   = 0x00000004
	REG_NOTIFY_CHANGE_SECURITY   = 0x00000008

	REG_OPTION_NON_VOLATILE   = 0x00000000
	REG_OPTION_VOLATILE       = 0x00000001
	REG_OPTION_CREATE_LINK    = 0x00000002
	REG_OPTION_BACKUP_RESTORE = 0x00000004
	REG_OPTION_OPEN_LINK      = 0x00000008

	KEY_QUERY_VALUE        = 0x0001
	KEY_SET_VALUE          = 0x0002
	KEY_CREATE_SUB_KEY     = 0x0004
	KEY_ENUMERATE_SUB_KEYS = 0x0008
	KEY_NOTIFY             = 0x0010
	KEY_CREATE_LINK        = 0x0020
	KEY_READ               = 0x20019
	KEY_WRITE              = 0x20006
	KEY_EXECUTE            = 0x20019
	KEY_ALL_ACCESS         = 0xF003F

	REG_SZ                  = 1
	REG_EXPAND_SZ           = 2
	REG_BINARY              = 3
	REG_DWORD               = 4
	REG_DWORD_LITTLE_ENDIAN = 4
	REG_DWORD_BIG_ENDIAN    = 5
	REG_LINK                = 6
	REG_MULTI_SZ            = 7
	REG_QWORD               = 11
	REG_QWORD_LITTLE_ENDIAN = 11
)

var (
	regAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	regKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegOpenKeyExW           = regAdvapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyExW         = regAdvapi32.NewProc("RegCreateKeyExW")
	procRegCloseKey             = regAdvapi32.NewProc("RegCloseKey")
	procRegQueryValueExW        = regAdvapi32.NewProc("RegQueryValueExW")
	procRegSetValueExW          = regAdvapi32.NewProc("RegSetValueExW")
	procRegDeleteValueW         = regAdvapi32.NewProc("RegDeleteValueW")
	procRegDeleteKeyW           = regAdvapi32.NewProc("RegDeleteKeyW")
	procRegEnumKeyExW           = regAdvapi32.NewProc("RegEnumKeyExW")
	procRegEnumValueW           = regAdvapi32.NewProc("RegEnumValueW")
	procRegNotifyChangeKeyValue = regAdvapi32.NewProc("RegNotifyChangeKeyValue")
)

func NewRegistryMonitor(cfg *config.RegistryConfig, logger *utils.Logger) *RegistryMonitor {
	return &RegistryMonitor{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.RegistryEvent, 1000),
		stopChan:  make(chan bool),
		agentID:   "",
		watchers:  make(map[string]*RegistryWatcher),
	}
}

func (rm *RegistryMonitor) Start() error {
	rm.logger.Info("Starting registry monitor...")
	rm.mu.Lock()
	rm.isStopping = false
	rm.mu.Unlock()

	// Validate paths
	if len(rm.config.Paths) == 0 {
		return fmt.Errorf("no registry paths configured for monitoring")
	}

	// Start watching each configured path
	for _, path := range rm.config.Paths {
		if err := rm.watchRegistryKey(path); err != nil {
			rm.logger.Warn("Failed to watch registry key %s: %v", path, err)
			continue
		}
	}

	// Start event processing goroutine
	go rm.processEvents()

	rm.logger.Info("Registry monitor started successfully")
	return nil
}

func (rm *RegistryMonitor) Stop() {
	rm.logger.Info("Stopping registry monitor...")
	rm.mu.Lock()
	rm.isStopping = true
	rm.mu.Unlock()

	// Signal stop
	close(rm.stopChan)

	// Close all watchers
	for _, watcher := range rm.watchers {
		if watcher.handle != 0 {
			procRegCloseKey.Call(uintptr(watcher.handle))
			watcher.handle = 0
		}
		close(watcher.events)
	}

	close(rm.eventChan)
	rm.logger.Info("Registry monitor stopped")
}

func (rm *RegistryMonitor) GetEventChannel() <-chan models.RegistryEvent {
	return rm.eventChan
}

func (rm *RegistryMonitor) SetAgentID(agentID string) {
	rm.agentID = agentID
}

func (rm *RegistryMonitor) watchRegistryKey(keyPath string) error {
	// Parse key path
	hKey, subKey, err := rm.parseRegistryPath(keyPath)
	if err != nil {
		return fmt.Errorf("failed to parse registry path %s: %w", keyPath, err)
	}

	// Open registry key
	var handle windows.Handle
	keyName, err := windows.UTF16PtrFromString(subKey)
	if err != nil {
		return fmt.Errorf("failed to convert key name to UTF16: %w", err)
	}

	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(keyName)),
		0,
		KEY_READ|KEY_NOTIFY,
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != 0 {
		return fmt.Errorf("failed to open registry key %s: %d", keyPath, ret)
	}

	// Create watcher
	watcher := &RegistryWatcher{
		keyPath: keyPath,
		handle:  handle,
		events:  make(chan models.RegistryEvent, 100),
	}

	rm.watchers[keyPath] = watcher

	// Start monitoring goroutine
	go rm.monitorRegistryKey(watcher)

	rm.logger.Info("Started monitoring registry key: %s", keyPath)
	return nil
}

func (rm *RegistryMonitor) monitorRegistryKey(watcher *RegistryWatcher) {
	for {
		select {
		case <-rm.stopChan:
			return
		default:
			// Create event for registry notification
			event, err := windows.CreateEvent(nil, 0, 0, nil)
			if err != nil {
				rm.logger.Error("Failed to create event for %s: %v", watcher.keyPath, err)
				time.Sleep(time.Second)
				continue
			}
			// Ensure we close the event handle each iteration

			// Wait for registry changes
			ret, _, _ := procRegNotifyChangeKeyValue.Call(
				uintptr(watcher.handle),
				1, // bWatchSubtree
				REG_NOTIFY_CHANGE_NAME|REG_NOTIFY_CHANGE_ATTRIBUTES|REG_NOTIFY_CHANGE_LAST_SET|REG_NOTIFY_CHANGE_SECURITY,
				uintptr(event),
				1, // fAsynchronous
			)

			if ret != 0 {
				windows.CloseHandle(event)
				rm.logger.Error("RegNotifyChangeKeyValue failed for %s: %d", watcher.keyPath, ret)
				time.Sleep(time.Second)
				continue
			}

			// Wait for the event to be signaled
			_, err = windows.WaitForSingleObject(event, windows.INFINITE)
			windows.CloseHandle(event)
			if err != nil {
				rm.logger.Error("WaitForSingleObject failed for %s: %v", watcher.keyPath, err)
				time.Sleep(time.Second)
				continue
			}

			// Process changes
			rm.mu.RLock()
			stopping := rm.isStopping
			rm.mu.RUnlock()
			if stopping || watcher.handle == 0 {
				return
			}
			rm.processRegistryChanges(watcher)
		}
	}
}

func (rm *RegistryMonitor) processRegistryChanges(watcher *RegistryWatcher) {
	// Enumerate values to detect changes
	values, err := rm.enumerateRegistryValues(watcher.handle)
	if err != nil {
		rm.mu.RLock()
		stopping := rm.isStopping
		rm.mu.RUnlock()
		if !stopping {
			rm.logger.Error("Failed to enumerate registry values for %s: %v", watcher.keyPath, err)
		}
		return
	}

	// Create events for each value
	for _, value := range values {
		rm.createRegistryEvent(watcher.keyPath, value, "value_modified")
	}

	// Enumerate subkeys to detect changes
	subkeys, err := rm.enumerateRegistrySubkeys(watcher.handle)
	if err != nil {
		rm.logger.Error("Failed to enumerate registry subkeys for %s: %v", watcher.keyPath, err)
		return
	}

	// Create events for each subkey
	for _, subkey := range subkeys {
		rm.createRegistryEvent(watcher.keyPath, subkey, "subkey_modified")
	}
}

func (rm *RegistryMonitor) enumerateRegistryValues(handle windows.Handle) ([]string, error) {
	var values []string
	var index uint32

	for {
		var valueName [256]uint16
		var valueNameSize uint32 = 256
		var valueType uint32
		var valueDataSize uint32

		ret, _, _ := procRegEnumValueW.Call(
			uintptr(handle),
			uintptr(index),
			uintptr(unsafe.Pointer(&valueName[0])),
			uintptr(unsafe.Pointer(&valueNameSize)),
			0,
			uintptr(unsafe.Pointer(&valueType)),
			0,
			uintptr(unsafe.Pointer(&valueDataSize)),
		)

		if ret == 259 { // ERROR_NO_MORE_ITEMS
			break
		}

		if ret != 0 {
			return nil, fmt.Errorf("RegEnumValueW failed: %d", ret)
		}

		valueNameStr := windows.UTF16ToString(valueName[:valueNameSize])
		values = append(values, valueNameStr)
		index++
	}

	return values, nil
}

func (rm *RegistryMonitor) enumerateRegistrySubkeys(handle windows.Handle) ([]string, error) {
	var subkeys []string
	var index uint32

	for {
		var subkeyName [256]uint16
		var subkeyNameSize uint32 = 256
		var classSize uint32
		var lastWriteTime windows.Filetime

		ret, _, _ := procRegEnumKeyExW.Call(
			uintptr(handle),
			uintptr(index),
			uintptr(unsafe.Pointer(&subkeyName[0])),
			uintptr(unsafe.Pointer(&subkeyNameSize)),
			0,
			0,
			uintptr(unsafe.Pointer(&classSize)),
			uintptr(unsafe.Pointer(&lastWriteTime)),
		)

		if ret == 259 { // ERROR_NO_MORE_ITEMS
			break
		}

		if ret != 0 {
			return nil, fmt.Errorf("RegEnumKeyExW failed: %d", ret)
		}

		subkeyNameStr := windows.UTF16ToString(subkeyName[:subkeyNameSize])
		subkeys = append(subkeys, subkeyNameStr)
		index++
	}

	return subkeys, nil
}

func (rm *RegistryMonitor) createRegistryEvent(keyPath, valueName, action string) {
	// Determine severity
	severity := rm.determineRegistrySeverity(keyPath, valueName)

	// Get value data if possible
	valueData, valueType := rm.getRegistryValueData(keyPath, valueName)

	// Create event
	event := models.RegistryEvent{
		Event: models.Event{
			ID:        rm.generateEventID(),
			AgentID:   rm.agentID,
			Timestamp: time.Now(),
			EventType: "registry_event",
			Severity:  severity,
			Source:    "registry_monitor",
		},
		Hive:      "",
		KeyPath:   keyPath,
		ValueName: valueName,
		ValueType: valueType,
		ValueData: valueData,
		UserID:    "",
		ProcessID: 0,
	}

	// Send event
	select {
	case rm.eventChan <- event:
		rm.logger.Debug("Registry event sent: %s %s\\%s", action, keyPath, valueName)
	default:
		rm.logger.Warn("Registry event channel full, dropping event")
	}
}

func (rm *RegistryMonitor) determineRegistrySeverity(keyPath, valueName string) string {
	// Check for suspicious registry keys
	if rm.isSuspiciousRegistryKey(keyPath, valueName) {
		return "high"
	}

	// Check for system registry keys
	if rm.isSystemRegistryKey(keyPath) {
		return "medium"
	}

	// Check for startup registry keys
	if rm.isStartupRegistryKey(keyPath, valueName) {
		return "high"
	}

	return "low"
}

func (rm *RegistryMonitor) isSuspiciousRegistryKey(keyPath, valueName string) bool {
	suspiciousPatterns := []string{
		"Run",
		"RunOnce",
		"RunServices",
		"RunServicesOnce",
		"Winlogon",
		"Shell",
		"Explorer",
		"Policies",
		"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"Software\\Microsoft\\Windows\\CurrentVersion\\Policies",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(keyPath), strings.ToLower(pattern)) ||
			strings.Contains(strings.ToLower(valueName), strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}

func (rm *RegistryMonitor) isSystemRegistryKey(keyPath string) bool {
	systemKeys := []string{
		"SYSTEM\\CurrentControlSet",
		"SOFTWARE\\Microsoft\\Windows NT",
		"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
		"HARDWARE\\DESCRIPTION",
	}

	for _, systemKey := range systemKeys {
		if strings.Contains(strings.ToLower(keyPath), strings.ToLower(systemKey)) {
			return true
		}
	}

	return false
}

func (rm *RegistryMonitor) isStartupRegistryKey(keyPath, valueName string) bool {
	startupKeys := []string{
		"Run",
		"RunOnce",
		"RunServices",
		"RunServicesOnce",
		"Winlogon\\Shell",
		"Winlogon\\Userinit",
		"Winlogon\\System",
	}

	for _, startupKey := range startupKeys {
		if strings.Contains(strings.ToLower(keyPath), strings.ToLower(startupKey)) ||
			strings.Contains(strings.ToLower(valueName), strings.ToLower(startupKey)) {
			return true
		}
	}

	return false
}

func (rm *RegistryMonitor) getRegistryValueData(keyPath, valueName string) (string, string) {
	// Parse key path
	hKey, subKey, err := rm.parseRegistryPath(keyPath)
	if err != nil {
		return "", ""
	}

	// Open registry key
	var handle windows.Handle
	keyName, err := windows.UTF16PtrFromString(subKey)
	if err != nil {
		return "", ""
	}

	ret, _, _ := procRegOpenKeyExW.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(keyName)),
		0,
		KEY_READ,
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != 0 {
		return "", ""
	}
	defer procRegCloseKey.Call(uintptr(handle))

	// Query value
	var valueType uint32
	var valueDataSize uint32

	valueNamePtr, err := windows.UTF16PtrFromString(valueName)
	if err != nil {
		return "", ""
	}

	ret, _, _ = procRegQueryValueExW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(valueNamePtr)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		0,
		uintptr(unsafe.Pointer(&valueDataSize)),
	)

	if ret != 0 {
		return "", ""
	}

	// Read value data
	valueData := make([]byte, valueDataSize)
	ret, _, _ = procRegQueryValueExW.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(valueNamePtr)),
		0,
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&valueData[0])),
		uintptr(unsafe.Pointer(&valueDataSize)),
	)

	if ret != 0 {
		return "", ""
	}

	// Convert to string based on type
	var valueStr string
	switch valueType {
	case REG_SZ, REG_EXPAND_SZ:
		valueStr = windows.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(&valueData[0]))[:valueDataSize/2])
	case REG_DWORD, REG_DWORD_BIG_ENDIAN:
		valueStr = fmt.Sprintf("%d", *(*uint32)(unsafe.Pointer(&valueData[0])))
	case REG_QWORD:
		valueStr = fmt.Sprintf("%d", *(*uint64)(unsafe.Pointer(&valueData[0])))
	default:
		valueStr = fmt.Sprintf("[Binary data, %d bytes]", len(valueData))
	}

	return valueStr, rm.registryTypeToString(valueType)
}

func (rm *RegistryMonitor) parseRegistryPath(path string) (uintptr, string, error) {
	parts := strings.SplitN(path, "\\", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid registry path format")
	}

	var hKey uintptr
	switch strings.ToUpper(parts[0]) {
	case "HKEY_LOCAL_MACHINE", "HKLM":
		hKey = HKEY_LOCAL_MACHINE
	case "HKEY_CURRENT_USER", "HKCU":
		hKey = HKEY_CURRENT_USER
	case "HKEY_USERS", "HKU":
		hKey = HKEY_USERS
	case "HKEY_CLASSES_ROOT", "HKCR":
		hKey = HKEY_CLASSES_ROOT
	default:
		return 0, "", fmt.Errorf("unknown registry hive: %s", parts[0])
	}

	return hKey, parts[1], nil
}

func (rm *RegistryMonitor) registryTypeToString(valueType uint32) string {
	switch valueType {
	case REG_SZ:
		return "REG_SZ"
	case REG_EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case REG_BINARY:
		return "REG_BINARY"
	case REG_DWORD:
		return "REG_DWORD"
	case REG_DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case REG_LINK:
		return "REG_LINK"
	case REG_MULTI_SZ:
		return "REG_MULTI_SZ"
	case REG_QWORD:
		return "REG_QWORD"
	default:
		return "REG_UNKNOWN"
	}
}

func (rm *RegistryMonitor) generateEventID() string {
	return fmt.Sprintf("registry_%d", time.Now().UnixNano())
}

func (rm *RegistryMonitor) processEvents() {
	for {
		select {
		case <-rm.stopChan:
			return
		case event := <-rm.eventChan:
			// Process registry event
			rm.logger.Debug("Processing registry event: %s", event.KeyPath)
		}
	}
}
