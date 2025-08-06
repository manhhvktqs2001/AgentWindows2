package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Agent   AgentDetails  `yaml:"agent"`
	Monitor MonitorConfig `yaml:"monitor"`
	Scanner ScannerConfig `yaml:"scanner"`
	Log     LogConfig     `yaml:"log"`
}

type ServerConfig struct {
	URL        string `yaml:"url"`         // "http://192.168.20.85:5000"
	APIKey     string `yaml:"api_key"`     // Agent authentication
	AuthToken  string `yaml:"auth_token"`  // Pre-shared registration token
	Timeout    int    `yaml:"timeout"`     // HTTP timeout seconds
	RetryCount int    `yaml:"retry_count"` // Retry failed requests
	TLSVerify  bool   `yaml:"tls_verify"`  // Verify TLS certificates
}

type AgentDetails struct {
	ID                string `yaml:"id"`                 // Unique agent ID
	Name              string `yaml:"name"`               // Agent name
	HeartbeatInterval int    `yaml:"heartbeat_interval"` // Heartbeat seconds
	EventBatchSize    int    `yaml:"event_batch_size"`   // Events per batch
	MaxQueueSize      int    `yaml:"max_queue_size"`     // Max event queue
}

type MonitorConfig struct {
	Files     FileMonitorConfig     `yaml:"files"`
	Processes ProcessMonitorConfig  `yaml:"processes"`
	Network   NetworkMonitorConfig  `yaml:"network"`
	Registry  RegistryMonitorConfig `yaml:"registry"` // Windows only
}

type FileMonitorConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Paths       []string `yaml:"paths"`         // Paths to monitor
	Recursive   bool     `yaml:"recursive"`     // Monitor subdirectories
	ScanOnWrite bool     `yaml:"scan_on_write"` // YARA scan on file write
	MaxFileSize string   `yaml:"max_file_size"` // Max file size to scan
	ExcludeExts []string `yaml:"exclude_exts"`  // Exclude extensions
}

type ProcessMonitorConfig struct {
	Enabled        bool     `yaml:"enabled"`
	ScanExecutable bool     `yaml:"scan_executable"` // YARA scan new processes
	MonitorCmdLine bool     `yaml:"monitor_cmdline"` // Monitor command lines
	ExcludeNames   []string `yaml:"exclude_names"`   // Exclude process names
}

type NetworkMonitorConfig struct {
	Enabled      bool  `yaml:"enabled"`
	MonitorTCP   bool  `yaml:"monitor_tcp"`
	MonitorUDP   bool  `yaml:"monitor_udp"`
	ExcludePorts []int `yaml:"exclude_ports"` // Exclude local ports
}

type RegistryMonitorConfig struct {
	Enabled bool     `yaml:"enabled"` // Windows only
	Keys    []string `yaml:"keys"`    // Registry keys to monitor
}

type ScannerConfig struct {
	YaraEnabled    bool   `yaml:"yara_enabled"`
	YaraRulesPath  string `yaml:"yara_rules_path"`  // Local YARA rules cache
	MaxScanThreads int    `yaml:"max_scan_threads"` // Max concurrent scans
	ScanTimeout    int    `yaml:"scan_timeout"`     // Scan timeout seconds
}

type LogConfig struct {
	Level    string `yaml:"level"`     // debug, info, warn, error
	Format   string `yaml:"format"`    // json, text
	FilePath string `yaml:"file_path"` // Log file path
	MaxSize  int    `yaml:"max_size"`  // Max log file size MB
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
		Monitor: MonitorConfig{
			Files: FileMonitorConfig{
				Enabled:     viper.GetBool("monitor.files.enabled"),
				Paths:       viper.GetStringSlice("monitor.files.paths"),
				Recursive:   viper.GetBool("monitor.files.recursive"),
				ScanOnWrite: viper.GetBool("monitor.files.scan_on_write"),
				MaxFileSize: viper.GetString("monitor.files.max_file_size"),
				ExcludeExts: viper.GetStringSlice("monitor.files.exclude_exts"),
			},
			Processes: ProcessMonitorConfig{
				Enabled:        viper.GetBool("monitor.processes.enabled"),
				ScanExecutable: viper.GetBool("monitor.processes.scan_executable"),
				MonitorCmdLine: viper.GetBool("monitor.processes.monitor_cmdline"),
				ExcludeNames:   viper.GetStringSlice("monitor.processes.exclude_names"),
			},
			Network: NetworkMonitorConfig{
				Enabled:      viper.GetBool("monitor.network.enabled"),
				MonitorTCP:   viper.GetBool("monitor.network.monitor_tcp"),
				MonitorUDP:   viper.GetBool("monitor.network.monitor_udp"),
				ExcludePorts: viper.GetIntSlice("monitor.network.exclude_ports"),
			},
			Registry: RegistryMonitorConfig{
				Enabled: viper.GetBool("monitor.registry.enabled"),
				Keys:    viper.GetStringSlice("monitor.registry.keys"),
			},
		},
		Scanner: ScannerConfig{
			YaraEnabled:    viper.GetBool("scanner.yara_enabled"),
			YaraRulesPath:  viper.GetString("scanner.yara_rules_path"),
			MaxScanThreads: viper.GetInt("scanner.max_scan_threads"),
			ScanTimeout:    viper.GetInt("scanner.scan_timeout"),
		},
		Log: LogConfig{
			Level:    viper.GetString("log.level"),
			Format:   viper.GetString("log.format"),
			FilePath: viper.GetString("log.file_path"),
			MaxSize:  viper.GetInt("log.max_size"),
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

	// Monitor defaults
	viper.SetDefault("monitor.files.enabled", true)
	viper.SetDefault("monitor.files.recursive", true)
	viper.SetDefault("monitor.files.scan_on_write", true)
	viper.SetDefault("monitor.files.max_file_size", "100MB")
	viper.SetDefault("monitor.files.exclude_exts", []string{".tmp", ".log", ".bak"})

	viper.SetDefault("monitor.processes.enabled", true)
	viper.SetDefault("monitor.processes.scan_executable", true)
	viper.SetDefault("monitor.processes.monitor_cmdline", true)
	viper.SetDefault("monitor.processes.exclude_names", []string{"explorer.exe", "dwm.exe", "winlogon.exe"})

	viper.SetDefault("monitor.network.enabled", true)
	viper.SetDefault("monitor.network.monitor_tcp", true)
	viper.SetDefault("monitor.network.monitor_udp", false)
	viper.SetDefault("monitor.network.exclude_ports", []int{135, 445, 5985})

	viper.SetDefault("monitor.registry.enabled", true)
	viper.SetDefault("monitor.registry.keys", []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	})

	// Scanner defaults
	viper.SetDefault("scanner.yara_enabled", true)
	viper.SetDefault("scanner.max_scan_threads", 4)
	viper.SetDefault("scanner.scan_timeout", 30)

	// Log defaults
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", "json")
	viper.SetDefault("log.file_path", "C:\\Program Files\\EDR-Agent\\logs\\agent.log")
	viper.SetDefault("log.max_size", 100)
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
		Monitor: MonitorConfig{
			Files: FileMonitorConfig{
				Enabled:     true,
				Paths:       []string{"C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows\\System32", "C:\\Users"},
				Recursive:   true,
				ScanOnWrite: true,
				MaxFileSize: "100MB",
				ExcludeExts: []string{".tmp", ".log", ".bak"},
			},
			Processes: ProcessMonitorConfig{
				Enabled:        true,
				ScanExecutable: true,
				MonitorCmdLine: true,
				ExcludeNames:   []string{"explorer.exe", "dwm.exe", "winlogon.exe"},
			},
			Network: NetworkMonitorConfig{
				Enabled:      true,
				MonitorTCP:   true,
				MonitorUDP:   false,
				ExcludePorts: []int{135, 445, 5985},
			},
			Registry: RegistryMonitorConfig{
				Enabled: true,
				Keys: []string{
					"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
					"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
					"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
				},
			},
		},
		Scanner: ScannerConfig{
			YaraEnabled:    true,
			YaraRulesPath:  "yara-rules",
			MaxScanThreads: 4,
			ScanTimeout:    30,
		},
		Log: LogConfig{
			Level:    "info",
			Format:   "json",
			FilePath: "C:\\Program Files\\EDR-Agent\\logs\\agent.log",
			MaxSize:  100,
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
		Monitor: MonitorConfig{
			Files: FileMonitorConfig{
				Enabled:     false,
				Paths:       []string{},
				Recursive:   false,
				ScanOnWrite: false,
				MaxFileSize: "100MB",
				ExcludeExts: []string{},
			},
			Processes: ProcessMonitorConfig{
				Enabled:        false,
				ScanExecutable: false,
				MonitorCmdLine: false,
				ExcludeNames:   []string{},
			},
			Network: NetworkMonitorConfig{
				Enabled:      false,
				MonitorTCP:   false,
				MonitorUDP:   false,
				ExcludePorts: []int{},
			},
			Registry: RegistryMonitorConfig{
				Enabled: false,
				Keys:    []string{},
			},
		},
		Scanner: ScannerConfig{
			YaraEnabled:    false,
			YaraRulesPath:  "",
			MaxScanThreads: 1,
			ScanTimeout:    30,
		},
		Log: LogConfig{
			Level:    "info",
			Format:   "text",
			FilePath: "agent.log",
			MaxSize:  10,
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
