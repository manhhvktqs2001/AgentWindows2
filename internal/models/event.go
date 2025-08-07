package models

import (
	"encoding/json"
	"time"
)

// Event represents a security event detected by the agent
type Event struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agent_id"`
	EventType    string                 `json:"event_type"`
	Timestamp    time.Time              `json:"timestamp"`
	Severity     string                 `json:"severity"`
	Category     string                 `json:"category"`
	Source       string                 `json:"source"`
	Data         map[string]interface{} `json:"data"`
	Hash         string                 `json:"hash,omitempty"`
	FilePath     string                 `json:"file_path,omitempty"`
	ProcessID    int                    `json:"process_id,omitempty"`
	ProcessName  string                 `json:"process_name,omitempty"`
	NetworkInfo  *NetworkInfo           `json:"network_info,omitempty"`
	RegistryInfo *RegistryInfo          `json:"registry_info,omitempty"`
	ThreatInfo   *ThreatInfo            `json:"threat_info,omitempty"`
}

// NetworkInfo contains network-related event data
type NetworkInfo struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"`
	Direction  string `json:"direction"` // inbound, outbound
	Domain     string `json:"domain,omitempty"`
}

// RegistryInfo contains registry-related event data
type RegistryInfo struct {
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name"`
	ValueType string `json:"value_type"`
	OldValue  string `json:"old_value,omitempty"`
	NewValue  string `json:"new_value,omitempty"`
	Action    string `json:"action"` // create, modify, delete
}

// ThreatInfo contains threat detection information
type ThreatInfo struct {
	ThreatType     string    `json:"threat_type"`
	ThreatName     string    `json:"threat_name"`
	Confidence     float64   `json:"confidence"`
	Severity       int       `json:"severity"`
	FilePath       string    `json:"file_path"`
	ProcessID      int       `json:"process_id"`
	ProcessName    string    `json:"process_name"`
	YaraRules      []string  `json:"yara_rules,omitempty"`
	MITRETechnique string    `json:"mitre_technique,omitempty"`
	Description    string    `json:"description"`
	Timestamp      time.Time `json:"timestamp"`
}

// FileEvent represents a file system event
type FileEvent struct {
	Event
	FileSize    int64  `json:"file_size"`
	FileType    string `json:"file_type"`
	FileHash    string `json:"file_hash"`
	Action      string `json:"action"` // create, modify, delete, access
	UserID      string `json:"user_id"`
	Permissions string `json:"permissions"`
}

func (fe *FileEvent) GetAgentID() string {
	return fe.AgentID
}

func (fe *FileEvent) GetTimestamp() time.Time {
	return fe.Timestamp
}

func (fe *FileEvent) GetType() string {
	return fe.EventType
}

func (fe *FileEvent) ToJSON() []byte {
	b, _ := json.Marshal(fe)
	return b
}

// ProcessEvent represents a process-related event
type ProcessEvent struct {
	Event
	ParentProcessID   int    `json:"parent_process_id"`
	ParentProcessName string `json:"parent_process_name"`
	CommandLine       string `json:"command_line"`
	WorkingDirectory  string `json:"working_directory"`
	UserID            string `json:"user_id"`
	SessionID         int    `json:"session_id"`
	IntegrityLevel    string `json:"integrity_level"`
}

func (pe *ProcessEvent) GetAgentID() string {
	return pe.AgentID
}

func (pe *ProcessEvent) GetTimestamp() time.Time {
	return pe.Timestamp
}

func (pe *ProcessEvent) GetType() string {
	return pe.EventType
}

func (pe *ProcessEvent) ToJSON() []byte {
	b, _ := json.Marshal(pe)
	return b
}

// NetworkEvent represents a network activity event
type NetworkEvent struct {
	Event
	ConnectionID  string `json:"connection_id"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
	Duration      int    `json:"duration"`
	Status        string `json:"status"`
}

func (ne *NetworkEvent) GetAgentID() string {
	return ne.AgentID
}

func (ne *NetworkEvent) GetTimestamp() time.Time {
	return ne.Timestamp
}

func (ne *NetworkEvent) GetType() string {
	return ne.EventType
}

func (ne *NetworkEvent) ToJSON() []byte {
	b, _ := json.Marshal(ne)
	return b
}

// RegistryEvent represents a registry modification event
type RegistryEvent struct {
	Event
	Hive      string `json:"hive"`
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name"`
	ValueType string `json:"value_type"`
	ValueData string `json:"value_data"`
	UserID    string `json:"user_id"`
	ProcessID int    `json:"process_id"`
}

func (re *RegistryEvent) GetAgentID() string {
	return re.AgentID
}

func (re *RegistryEvent) GetTimestamp() time.Time {
	return re.Timestamp
}

func (re *RegistryEvent) GetType() string {
	return re.EventType
}

func (re *RegistryEvent) ToJSON() []byte {
	b, _ := json.Marshal(re)
	return b
}

// MemoryEvent represents a memory-related event
type MemoryEvent struct {
	Event
	ProcessID    int    `json:"process_id"`
	ProcessName  string `json:"process_name"`
	MemoryRegion string `json:"memory_region"`
	Action       string `json:"action"` // allocation, protection, execution
	Size         int64  `json:"size"`
	Protection   string `json:"protection"`
}
