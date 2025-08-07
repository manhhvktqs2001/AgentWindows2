package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// ResponseConfig cấu hình cho Response System
type ResponseConfig struct {
	NotificationSettings NotificationSettings `yaml:"notification_settings"`
	SeverityThresholds   SeverityThresholds   `yaml:"severity_thresholds"`
	UserInteraction      UserInteraction      `yaml:"user_interaction"`
	Customization        Customization        `yaml:"customization"`
}

// NotificationSettings cấu hình thông báo
type NotificationSettings struct {
	ToastEnabled        bool `yaml:"toast_enabled"`
	SystemTrayEnabled   bool `yaml:"system_tray_enabled"`
	DesktopAlertEnabled bool `yaml:"desktop_alert_enabled"`
	SoundEnabled        bool `yaml:"sound_enabled"`
	TimeoutSeconds      int  `yaml:"timeout_seconds"`
}

// SeverityThresholds ngưỡng severity
type SeverityThresholds struct {
	ShowUserAlerts int `yaml:"show_user_alerts"`
	AutoQuarantine int `yaml:"auto_quarantine"`
	BlockExecution int `yaml:"block_execution"`
}

// UserInteraction cấu hình tương tác người dùng
type UserInteraction struct {
	AllowUserOverride    bool `yaml:"allow_user_override"`
	RequireAdminForAllow bool `yaml:"require_admin_for_allow"`
	TimeoutSeconds       int  `yaml:"timeout_seconds"`
}

// Customization cấu hình tùy chỉnh
type Customization struct {
	CompanyBranding bool   `yaml:"company_branding"`
	CustomMessages  bool   `yaml:"custom_messages"`
	Language        string `yaml:"language"`
}

// Config cấu hình chính của agent
type Config struct {
	Agent      AgentDetails     `yaml:"agent"`
	Server     ServerConfig     `yaml:"server"`
	Yara       YaraConfig       `yaml:"yara"`
	Monitoring MonitoringConfig `yaml:"monitoring"`
	Response   ResponseConfig   `yaml:"response"`
	Log        LogConfig        `yaml:"logging"`
}

type ServerConfig struct {
	URL              string `yaml:"url"`               // "http://192.168.20.85:5000"
	APIKey           string `yaml:"api_key"`           // Agent authentication
	AuthToken        string `yaml:"auth_token"`        // Pre-shared registration token
	WebSocketEnabled bool   `yaml:"websocket_enabled"` // Enable WebSocket connection
	Timeout          int    `yaml:"timeout"`           // HTTP timeout seconds
	RetryCount       int    `yaml:"retry_count"`       // Retry failed requests
	TLSVerify        bool   `yaml:"tls_verify"`        // Verify TLS certificates
}

type AgentDetails struct {
	ID                string `yaml:"id"`                 // Unique agent ID
	Name              string `yaml:"name"`               // Agent name
	HeartbeatInterval int    `yaml:"heartbeat_interval"` // Heartbeat seconds
	EventBatchSize    int    `yaml:"event_batch_size"`   // Events per batch
	MaxQueueSize      int    `yaml:"max_queue_size"`     // Max event queue
	MaxMemoryUsage    string `yaml:"max_memory_usage"`   // Max memory usage
}

type MonitoringConfig struct {
	FileSystem FileSystemConfig `yaml:"file_system"`
	Processes  ProcessConfig    `yaml:"processes"`
	Network    NetworkConfig    `yaml:"network"`
	Registry   RegistryConfig   `yaml:"registry"`
}

type FileSystemConfig struct {
	Enabled           bool     `yaml:"enabled"`
	Paths             []string `yaml:"paths"`              // Paths to monitor
	ExcludeExtensions []string `yaml:"exclude_extensions"` // Exclude extensions
	RealTimeScan      bool     `yaml:"real_time_scan"`     // Real-time scanning
	Recursive         bool     `yaml:"recursive"`          // Monitor subdirectories
	MaxFileSize       string   `yaml:"max_file_size"`      // Max file size to scan
}

type ProcessConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	ScanExecutables         bool     `yaml:"scan_executables"`          // YARA scan new processes
	MonitorInjections       bool     `yaml:"monitor_injections"`        // Monitor code injections
	TrackNetworkConnections bool     `yaml:"track_network_connections"` // Track network connections
	MonitorCmdLine          bool     `yaml:"monitor_cmdline"`           // Monitor command lines
	ExcludeNames            []string `yaml:"exclude_names"`             // Exclude process names
}

type NetworkConfig struct {
	Enabled           bool  `yaml:"enabled"`
	MonitorDNS        bool  `yaml:"monitor_dns"`         // Monitor DNS queries
	BlockMaliciousIPs bool  `yaml:"block_malicious_ips"` // Block malicious IPs
	CapturePackets    bool  `yaml:"capture_packets"`     // Capture network packets
	MonitorTCP        bool  `yaml:"monitor_tcp"`         // Monitor TCP connections
	MonitorUDP        bool  `yaml:"monitor_udp"`         // Monitor UDP connections
	ExcludePorts      []int `yaml:"exclude_ports"`       // Exclude local ports
}

type RegistryConfig struct {
	Enabled               bool     `yaml:"enabled"`                 // Windows only
	MonitorAutostart      bool     `yaml:"monitor_autostart"`       // Monitor autostart entries
	TrackSecuritySettings bool     `yaml:"track_security_settings"` // Track security settings
	Keys                  []string `yaml:"keys"`                    // Registry keys to monitor
}

type YaraConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AutoUpdate     bool     `yaml:"auto_update"`
	UpdateInterval string   `yaml:"update_interval"`
	RulesSource    string   `yaml:"rules_source"`
	Categories     []string `yaml:"categories"`
	MaxScanThreads int      `yaml:"max_scan_threads"`
	ScanTimeout    int      `yaml:"scan_timeout"`
	RulesPath      string   `yaml:"rules_path"`
}

type LogConfig struct {
	Level     string `yaml:"level"`       // debug, info, warn, error
	Format    string `yaml:"format"`      // json, text
	FilePath  string `yaml:"file_path"`   // Log file path
	MaxSize   string `yaml:"max_size"`    // Max log file size
	Compress  bool   `yaml:"compress"`    // Compress log files
	MaxSizeMB int    `yaml:"max_size_mb"` // Max size in MB
}

// Load configuration from file
func Load(configPath string) (*Config, error) {
	// Set default values
	setDefaults()

	// Read config file
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("C:\\Program Files\\EDR-Agent")
	}

	// Environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("EDR_AGENT")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, use defaults
		fmt.Println("⚠️  Config file not found, using defaults")
	} else {
		fmt.Printf("✅ Using config file: %s\n", viper.ConfigFileUsed())
	}

	// Debug: Print all config values
	fmt.Printf("DEBUG: All config keys: %v\n", viper.AllKeys())

	// Debug: Print specific values
	fmt.Printf("DEBUG: agent.heartbeat_interval = %v\n", viper.Get("agent.heartbeat_interval"))
	fmt.Printf("DEBUG: server.url = %v\n", viper.Get("server.url"))
	fmt.Printf("DEBUG: server.api_key = %v\n", viper.Get("server.api_key"))

	// Manually set config values to avoid unmarshaling issues
	config := Config{
		Server: ServerConfig{
			URL:        viper.GetString("server.url"),
			APIKey:     viper.GetString("server.api_key"),
			AuthToken:  viper.GetString("server.auth_token"),
			Timeout:    viper.GetInt("server.timeout"),
			RetryCount: viper.GetInt("server.retry_count"),
			TLSVerify:  viper.GetBool("server.tls_verify"),
		},
		Agent: AgentDetails{
			ID:                viper.GetString("agent.id"),
			Name:              viper.GetString("agent.name"),
			HeartbeatInterval: viper.GetInt("agent.heartbeat_interval"),
			EventBatchSize:    viper.GetInt("agent.event_batch_size"),
			MaxQueueSize:      viper.GetInt("agent.max_queue_size"),
		},
		Monitoring: MonitoringConfig{
			FileSystem: FileSystemConfig{
				Enabled:           viper.GetBool("monitoring.file_system.enabled"),
				Paths:             viper.GetStringSlice("monitoring.file_system.paths"),
				ExcludeExtensions: viper.GetStringSlice("monitoring.file_system.exclude_extensions"),
				RealTimeScan:      viper.GetBool("monitoring.file_system.real_time_scan"),
				Recursive:         viper.GetBool("monitoring.file_system.recursive"),
				MaxFileSize:       viper.GetString("monitoring.file_system.max_file_size"),
			},
			Processes: ProcessConfig{
				Enabled:                 viper.GetBool("monitoring.processes.enabled"),
				ScanExecutables:         viper.GetBool("monitoring.processes.scan_executables"),
				MonitorInjections:       viper.GetBool("monitoring.processes.monitor_injections"),
				TrackNetworkConnections: viper.GetBool("monitoring.processes.track_network_connections"),
				MonitorCmdLine:          viper.GetBool("monitoring.processes.monitor_cmdline"),
				ExcludeNames:            viper.GetStringSlice("monitoring.processes.exclude_names"),
			},
			Network: NetworkConfig{
				Enabled:           viper.GetBool("monitoring.network.enabled"),
				MonitorDNS:        viper.GetBool("monitoring.network.monitor_dns"),
				BlockMaliciousIPs: viper.GetBool("monitoring.network.block_malicious_ips"),
				CapturePackets:    viper.GetBool("monitoring.network.capture_packets"),
				MonitorTCP:        viper.GetBool("monitoring.network.monitor_tcp"),
				MonitorUDP:        viper.GetBool("monitoring.network.monitor_udp"),
				ExcludePorts:      viper.GetIntSlice("monitoring.network.exclude_ports"),
			},
			Registry: RegistryConfig{
				Enabled:               viper.GetBool("monitoring.registry.enabled"),
				MonitorAutostart:      viper.GetBool("monitoring.registry.monitor_autostart"),
				TrackSecuritySettings: viper.GetBool("monitoring.registry.track_security_settings"),
				Keys:                  viper.GetStringSlice("monitoring.registry.keys"),
			},
		},
		Yara: YaraConfig{
			Enabled:        viper.GetBool("yara.enabled"),
			AutoUpdate:     viper.GetBool("yara.auto_update"),
			UpdateInterval: viper.GetString("yara.update_interval"),
			RulesSource:    viper.GetString("yara.rules_source"),
			Categories:     viper.GetStringSlice("yara.categories"),
			MaxScanThreads: viper.GetInt("yara.max_scan_threads"),
			ScanTimeout:    viper.GetInt("yara.scan_timeout"),
			RulesPath:      viper.GetString("yara.rules_path"),
		},
		Response: ResponseConfig{
			NotificationSettings: NotificationSettings{
				ToastEnabled:        viper.GetBool("response.notification_settings.toast_enabled"),
				SystemTrayEnabled:   viper.GetBool("response.notification_settings.system_tray_enabled"),
				DesktopAlertEnabled: viper.GetBool("response.notification_settings.desktop_alert_enabled"),
				SoundEnabled:        viper.GetBool("response.notification_settings.sound_enabled"),
				TimeoutSeconds:      viper.GetInt("response.notification_settings.timeout_seconds"),
			},
			SeverityThresholds: SeverityThresholds{
				ShowUserAlerts: viper.GetInt("response.severity_thresholds.show_user_alerts"),
				AutoQuarantine: viper.GetInt("response.severity_thresholds.auto_quarantine"),
				BlockExecution: viper.GetInt("response.severity_thresholds.block_execution"),
			},
			UserInteraction: UserInteraction{
				AllowUserOverride:    viper.GetBool("response.user_interaction.allow_user_override"),
				RequireAdminForAllow: viper.GetBool("response.user_interaction.require_admin_for_allow"),
				TimeoutSeconds:       viper.GetInt("response.user_interaction.timeout_seconds"),
			},
			Customization: Customization{
				CompanyBranding: viper.GetBool("response.customization.company_branding"),
				CustomMessages:  viper.GetBool("response.customization.custom_messages"),
				Language:        viper.GetString("response.customization.language"),
			},
		},
		Log: LogConfig{
			Level:    viper.GetString("logging.level"),
			Format:   viper.GetString("logging.format"),
			FilePath: viper.GetString("logging.file_path"),
			MaxSize:  viper.GetString("logging.max_size"),
		},
	}

	// Debug: Print the unmarshaled config
	fmt.Printf("DEBUG: Unmarshaled config - Agent: %+v\n", config.Agent)
	fmt.Printf("DEBUG: Unmarshaled config - Server: %+v\n", config.Server)

	// Validate configuration
	// if err := validateConfig(&config); err != nil {
	// 	return nil, fmt.Errorf("invalid configuration: %w", err)
	// }

	// Debug: Print heartbeat interval value
	fmt.Printf("DEBUG: Heartbeat interval = %d\n", config.Agent.HeartbeatInterval)

	// Set agent name to hostname if not set
	if config.Agent.Name == "" {
		hostname, err := os.Hostname()
		if err == nil {
			config.Agent.Name = hostname
		}
	}

	return &config, nil
}

// Set default values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.url", "http://192.168.20.85:5000")
	viper.SetDefault("server.timeout", 30)
	viper.SetDefault("server.retry_count", 3)
	viper.SetDefault("server.tls_verify", false)

	// Agent defaults
	viper.SetDefault("agent.heartbeat_interval", 30)
	viper.SetDefault("agent.event_batch_size", 100)
	viper.SetDefault("agent.max_queue_size", 10000)

	// Monitoring defaults
	viper.SetDefault("monitoring.file_system.enabled", true)
	viper.SetDefault("monitoring.file_system.recursive", true)
	viper.SetDefault("monitoring.file_system.real_time_scan", true)
	viper.SetDefault("monitoring.file_system.max_file_size", "100MB")
	viper.SetDefault("monitoring.file_system.exclude_extensions", []string{".tmp", ".log", ".bak"})

	viper.SetDefault("monitoring.processes.enabled", true)
	viper.SetDefault("monitoring.processes.scan_executables", true)
	viper.SetDefault("monitoring.processes.monitor_injections", true)
	viper.SetDefault("monitoring.processes.track_network_connections", true)
	viper.SetDefault("monitoring.processes.monitor_cmdline", true)
	viper.SetDefault("monitoring.processes.exclude_names", []string{"explorer.exe", "dwm.exe", "winlogon.exe"})

	viper.SetDefault("monitoring.network.enabled", true)
	viper.SetDefault("monitoring.network.monitor_dns", true)
	viper.SetDefault("monitoring.network.block_malicious_ips", false)
	viper.SetDefault("monitoring.network.capture_packets", false)
	viper.SetDefault("monitoring.network.monitor_tcp", true)
	viper.SetDefault("monitoring.network.monitor_udp", false)
	viper.SetDefault("monitoring.network.exclude_ports", []int{135, 445, 5985})

	viper.SetDefault("monitoring.registry.enabled", true)
	viper.SetDefault("monitoring.registry.monitor_autostart", true)
	viper.SetDefault("monitoring.registry.track_security_settings", true)
	viper.SetDefault("monitoring.registry.keys", []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	})

	// Yara defaults
	viper.SetDefault("yara.enabled", true)
	viper.SetDefault("yara.auto_update", true)
	viper.SetDefault("yara.update_interval", "24h")
	viper.SetDefault("yara.rules_source", "local")
	viper.SetDefault("yara.categories", []string{"malware", "backdoor", "trojan", "ransomware"})
	viper.SetDefault("yara.max_scan_threads", 4)
	viper.SetDefault("yara.scan_timeout", 30)
	viper.SetDefault("yara.rules_path", "yara-rules")

	// Response defaults
	viper.SetDefault("response.notification_settings.toast_enabled", true)
	viper.SetDefault("response.notification_settings.system_tray_enabled", true)
	viper.SetDefault("response.notification_settings.desktop_alert_enabled", true)
	viper.SetDefault("response.notification_settings.sound_enabled", true)
	viper.SetDefault("response.notification_settings.timeout_seconds", 10)
	viper.SetDefault("response.severity_thresholds.show_user_alerts", 1)
	viper.SetDefault("response.severity_thresholds.auto_quarantine", 2)
	viper.SetDefault("response.severity_thresholds.block_execution", 3)
	viper.SetDefault("response.user_interaction.allow_user_override", false)
	viper.SetDefault("response.user_interaction.require_admin_for_allow", true)
	viper.SetDefault("response.user_interaction.timeout_seconds", 30)
	viper.SetDefault("response.customization.company_branding", false)
	viper.SetDefault("response.customization.custom_messages", false)
	viper.SetDefault("response.customization.language", "en")

	// Log defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.file_path", "C:\\Program Files\\EDR-Agent\\logs\\agent.log")
	viper.SetDefault("logging.max_size", "100MB")
}

// Validate configuration
func validateConfig(config *Config) error {
	if config.Server.URL == "" {
		return fmt.Errorf("server URL cannot be empty")
	}

	if config.Agent.HeartbeatInterval < 10 {
		return fmt.Errorf("heartbeat interval must be at least 10 seconds")
	}

	if config.Agent.EventBatchSize < 1 {
		return fmt.Errorf("event batch size must be at least 1")
	}

	if config.Agent.MaxQueueSize < 100 {
		return fmt.Errorf("max queue size must be at least 100")
	}

	return nil
}

// Save configuration to file
func Save(config *Config, filePath string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Create default configuration file
func CreateDefaultConfig(filePath string) error {
	config := &Config{
		Server: ServerConfig{
			URL:        "http://192.168.20.85:5000",
			Timeout:    30,
			RetryCount: 3,
			TLSVerify:  false,
		},
		Agent: AgentDetails{
			HeartbeatInterval: 30,
			EventBatchSize:    100,
			MaxQueueSize:      10000,
		},
		Monitoring: MonitoringConfig{
			FileSystem: FileSystemConfig{
				Enabled:           true,
				Paths:             []string{"C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows\\System32", "C:\\Users"},
				Recursive:         true,
				RealTimeScan:      true,
				MaxFileSize:       "100MB",
				ExcludeExtensions: []string{".tmp", ".log", ".bak"},
			},
			Processes: ProcessConfig{
				Enabled:                 true,
				ScanExecutables:         true,
				MonitorInjections:       true,
				TrackNetworkConnections: true,
				MonitorCmdLine:          true,
				ExcludeNames:            []string{"explorer.exe", "dwm.exe", "winlogon.exe"},
			},
			Network: NetworkConfig{
				Enabled:           true,
				MonitorDNS:        true,
				BlockMaliciousIPs: false,
				CapturePackets:    false,
				MonitorTCP:        true,
				MonitorUDP:        false,
				ExcludePorts:      []int{135, 445, 5985},
			},
			Registry: RegistryConfig{
				Enabled:               true,
				MonitorAutostart:      true,
				TrackSecuritySettings: true,
				Keys: []string{
					"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
					"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
					"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
				},
			},
		},
		Yara: YaraConfig{
			Enabled:        true,
			AutoUpdate:     true,
			UpdateInterval: "24h",
			RulesSource:    "local",
			Categories:     []string{"malware", "backdoor", "trojan", "ransomware"},
			MaxScanThreads: 4,
			ScanTimeout:    30,
			RulesPath:      "yara-rules",
		},
		Response: ResponseConfig{
			NotificationSettings: NotificationSettings{
				ToastEnabled:        true,
				SystemTrayEnabled:   true,
				DesktopAlertEnabled: true,
				SoundEnabled:        true,
				TimeoutSeconds:      10,
			},
			SeverityThresholds: SeverityThresholds{
				ShowUserAlerts: 1,
				AutoQuarantine: 2,
				BlockExecution: 3,
			},
			UserInteraction: UserInteraction{
				AllowUserOverride:    false,
				RequireAdminForAllow: true,
				TimeoutSeconds:       30,
			},
			Customization: Customization{
				CompanyBranding: false,
				CustomMessages:  false,
				Language:        "en",
			},
		},
		Log: LogConfig{
			Level:    "info",
			Format:   "json",
			FilePath: "C:\\Program Files\\EDR-Agent\\logs\\agent.log",
			MaxSize:  "100MB",
		},
	}

	return Save(config, filePath)
}

// LoadOrCreate tải cấu hình từ file hoặc tạo file mặc định nếu không tồn tại
func LoadOrCreate(configPath string) (*Config, error) {
	// Thử load file cấu hình hiện có
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			return Load(configPath)
		}
	}

	// File không tồn tại, tạo cấu hình mặc định
	config := createDefaultConfig()

	// Lưu cấu hình mặc định
	if configPath != "" {
		if err := Save(config, configPath); err != nil {
			// Log warning nhưng vẫn tiếp tục với cấu hình in-memory
			fmt.Printf("⚠️  Failed to save default config to %s: %v\n", configPath, err)
		} else {
			fmt.Printf("✅ Created default config file: %s\n", configPath)
		}
	}

	return config, nil
}

// createDefaultConfig tạo cấu hình mặc định
func createDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			URL:        "http://192.168.20.85:5000",
			APIKey:     "f93ac1d1d7b64f07bd32c81e6ab8423e4cb7631f2051c9d8a2d340c5be3a4a9e",
			AuthToken:  "edr_system_auth_2025", // Pre-shared registration token
			Timeout:    30,
			RetryCount: 3,
			TLSVerify:  false,
		},
		Agent: AgentDetails{
			ID:                "", // Sẽ được điền sau khi đăng ký
			Name:              getDefaultAgentName(),
			HeartbeatInterval: 60,
			EventBatchSize:    100,
			MaxQueueSize:      10000,
		},
		Monitoring: MonitoringConfig{
			FileSystem: FileSystemConfig{
				Enabled:           false,
				Paths:             []string{},
				Recursive:         false,
				RealTimeScan:      false,
				MaxFileSize:       "100MB",
				ExcludeExtensions: []string{},
			},
			Processes: ProcessConfig{
				Enabled:                 false,
				ScanExecutables:         false,
				MonitorInjections:       false,
				TrackNetworkConnections: false,
				MonitorCmdLine:          false,
				ExcludeNames:            []string{},
			},
			Network: NetworkConfig{
				Enabled:           false,
				MonitorDNS:        false,
				BlockMaliciousIPs: false,
				CapturePackets:    false,
				MonitorTCP:        false,
				MonitorUDP:        false,
				ExcludePorts:      []int{},
			},
			Registry: RegistryConfig{
				Enabled:               false,
				MonitorAutostart:      false,
				TrackSecuritySettings: false,
				Keys:                  []string{},
			},
		},
		Yara: YaraConfig{
			Enabled:        false,
			AutoUpdate:     false,
			UpdateInterval: "1h",
			RulesSource:    "local",
			Categories:     []string{},
			MaxScanThreads: 1,
			ScanTimeout:    30,
			RulesPath:      "",
		},
		Response: ResponseConfig{
			NotificationSettings: NotificationSettings{
				ToastEnabled:        false,
				SystemTrayEnabled:   false,
				DesktopAlertEnabled: false,
				SoundEnabled:        false,
				TimeoutSeconds:      0,
			},
			SeverityThresholds: SeverityThresholds{
				ShowUserAlerts: 0,
				AutoQuarantine: 0,
				BlockExecution: 0,
			},
			UserInteraction: UserInteraction{
				AllowUserOverride:    false,
				RequireAdminForAllow: false,
				TimeoutSeconds:       0,
			},
			Customization: Customization{
				CompanyBranding: false,
				CustomMessages:  false,
				Language:        "",
			},
		},
		Log: LogConfig{
			Level:    "info",
			Format:   "text",
			FilePath: "agent.log",
			MaxSize:  "10MB",
		},
	}
}

// getDefaultAgentName tạo tên agent mặc định dựa trên hostname
func getDefaultAgentName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "edr-agent-windows"
	}
	return fmt.Sprintf("edr-agent-%s", hostname)
}

// SaveWithBackup lưu cấu hình và tạo backup
func SaveWithBackup(config *Config, filePath string) error {
	// Tạo backup nếu file hiện có
	if _, err := os.Stat(filePath); err == nil {
		backupPath := filePath + ".backup"
		if err := copyFile(filePath, backupPath); err != nil {
			fmt.Printf("⚠️  Failed to create backup: %v\n", err)
		}
	}

	return Save(config, filePath)
}

// copyFile sao chép file
func copyFile(src, dst string) error {
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

	_, err = destFile.ReadFrom(sourceFile)
	return err
}

// ValidateAndFix kiểm tra và sửa các giá trị cấu hình không hợp lệ
func ValidateAndFix(config *Config) {
	// Sửa heartbeat interval
	if config.Agent.HeartbeatInterval < 10 {
		config.Agent.HeartbeatInterval = 30
		fmt.Println("⚠️  Fixed heartbeat interval to 30 seconds")
	}

	// Sửa event batch size
	if config.Agent.EventBatchSize < 1 {
		config.Agent.EventBatchSize = 100
		fmt.Println("⚠️  Fixed event batch size to 100")
	}

	// Sửa max queue size
	if config.Agent.MaxQueueSize < 100 {
		config.Agent.MaxQueueSize = 10000
		fmt.Println("⚠️  Fixed max queue size to 10000")
	}

	// Sửa server URL
	if config.Server.URL == "" {
		config.Server.URL = "http://192.168.20.85:5000"
		fmt.Println("⚠️  Fixed server URL to default")
	}

	// Sửa agent name
	if config.Agent.Name == "" {
		config.Agent.Name = getDefaultAgentName()
		fmt.Printf("⚠️  Fixed agent name to %s\n", config.Agent.Name)
	}
}
