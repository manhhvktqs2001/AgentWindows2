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
	URL          string `yaml:"url"`           // "http://192.168.20.85:5000"
	APIKey       string `yaml:"api_key"`       // Agent authentication
	Timeout      int    `yaml:"timeout"`       // HTTP timeout seconds
	RetryCount   int    `yaml:"retry_count"`   // Retry failed requests
	TLSVerify    bool   `yaml:"tls_verify"`    // Verify TLS certificates
}

type AgentDetails struct {
	ID               string `yaml:"id"`                // Unique agent ID
	Name             string `yaml:"name"`              // Agent name
	HeartbeatInterval int   `yaml:"heartbeat_interval"` // Heartbeat seconds
	EventBatchSize   int    `yaml:"event_batch_size"`  // Events per batch
	MaxQueueSize     int    `yaml:"max_queue_size"`    // Max event queue
}

type MonitorConfig struct {
	Files     FileMonitorConfig     `yaml:"files"`
	Processes ProcessMonitorConfig  `yaml:"processes"`
	Network   NetworkMonitorConfig  `yaml:"network"`
	Registry  RegistryMonitorConfig `yaml:"registry"`  // Windows only
}

type FileMonitorConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Paths         []string `yaml:"paths"`          // Paths to monitor
	Recursive     bool     `yaml:"recursive"`      // Monitor subdirectories
	ScanOnWrite   bool     `yaml:"scan_on_write"`  // YARA scan on file write
	MaxFileSize   string   `yaml:"max_file_size"`  // Max file size to scan
	ExcludeExts   []string `yaml:"exclude_exts"`   // Exclude extensions
}

type ProcessMonitorConfig struct {
	Enabled        bool     `yaml:"enabled"`
	ScanExecutable bool     `yaml:"scan_executable"` // YARA scan new processes
	MonitorCmdLine bool     `yaml:"monitor_cmdline"` // Monitor command lines
	ExcludeNames   []string `yaml:"exclude_names"`   // Exclude process names
}

type NetworkMonitorConfig struct {
	Enabled      bool     `yaml:"enabled"`
	MonitorTCP   bool     `yaml:"monitor_tcp"`
	MonitorUDP   bool     `yaml:"monitor_udp"`
	ExcludePorts []int    `yaml:"exclude_ports"`  // Exclude local ports
}

type RegistryMonitorConfig struct {
	Enabled bool     `yaml:"enabled"`           // Windows only
	Keys    []string `yaml:"keys"`              // Registry keys to monitor
}

type ScannerConfig struct {
	YaraEnabled     bool   `yaml:"yara_enabled"`
	YaraRulesPath   string `yaml:"yara_rules_path"`   // Local YARA rules cache
	MaxScanThreads  int    `yaml:"max_scan_threads"`  // Max concurrent scans
	ScanTimeout     int    `yaml:"scan_timeout"`      // Scan timeout seconds
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

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

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