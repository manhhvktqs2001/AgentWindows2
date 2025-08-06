# EDR Agent Windows

Endpoint Detection and Response Agent for Windows systems.

## Features

- **File Monitoring**: Real-time file system monitoring using Windows ReadDirectoryChangesW API
- **Process Monitoring**: Process creation/termination monitoring (WMI implementation pending)
- **Network Monitoring**: TCP/UDP connection monitoring (Windows API implementation pending)
- **Registry Monitoring**: Registry key change monitoring (Windows API implementation pending)
- **YARA Scanning**: Malware detection using YARA rules
- **Windows Service**: Runs as a Windows service
- **Server Communication**: Communicates with EDR server at 192.168.20.85:5000

## Requirements

- Windows 10/11 or Windows Server 2016+
- Go 1.21+
- Administrator privileges for service installation

## Building

```powershell
# Build the agent
.\build.ps1

# Build with custom version
.\build.ps1 -Version "1.0.1"
```

## Installation

### Automatic Installation

```powershell
# Run installer
.\dist\install.ps1

# Uninstall
.\dist\install.ps1 -Uninstall
```

### Manual Installation

1. Copy `edr-agent.exe` and `config.yaml` to `C:\Program Files\EDR-Agent\`
2. Edit `config.yaml` to set your agent configuration
3. Install as Windows service:
   ```powershell
   sc.exe create "EDR-Agent" binPath= "C:\Program Files\EDR-Agent\edr-agent.exe" start= auto
   sc.exe description "EDR-Agent" "Endpoint Detection and Response Agent"
   Start-Service "EDR-Agent"
   ```

## Configuration

Edit `config.yaml` to configure the agent:

```yaml
server:
  url: "http://192.168.20.85:5000"  # EDR Server URL
  api_key: ""  # Will be set during registration

monitor:
  files:
    enabled: true
    paths:
      - "C:\\Program Files"
      - "C:\\Windows\\System32"
    scan_on_write: true  # YARA scan on file creation
```

## Usage

### Command Line Options

```powershell
# Show version
.\edr-agent.exe -version

# Install service
.\edr-agent.exe -install

# Uninstall service
.\edr-agent.exe -uninstall

# Start service
.\edr-agent.exe -start

# Stop service
.\edr-agent.exe -stop

# Check service status
.\edr-agent.exe -status

# Run as console application
.\edr-agent.exe -config "path/to/config.yaml"
```

### Service Management

```powershell
# Start service
Start-Service "EDR-Agent"

# Stop service
Stop-Service "EDR-Agent"

# Check status
Get-Service "EDR-Agent"

# View logs
Get-Content "C:\Program Files\EDR-Agent\logs\agent.log" -Tail 50
```

## Architecture

```
AgentWindows/
├── main.go                    # Entry point
├── config.yaml               # Configuration file
├── build.ps1                 # Build script
├── internal/
│   ├── agent/               # Main agent logic
│   ├── config/              # Configuration management
│   ├── communication/       # Server communication
│   ├── monitoring/          # System monitoring
│   │   ├── file_monitor.go  # File system monitoring
│   │   ├── process_monitor.go # Process monitoring
│   │   ├── network_monitor.go # Network monitoring
│   │   └── registry_monitor.go # Registry monitoring
│   ├── scanner/             # YARA scanning
│   ├── service/             # Windows service
│   └── utils/               # Utilities
└── dist/                    # Build output
```

## Monitoring Capabilities

### File Monitoring
- Monitors file creation, modification, deletion, and renaming
- Uses Windows ReadDirectoryChangesW API for real-time monitoring
- Configurable paths and file type exclusions
- YARA scanning on file creation

### Process Monitoring
- Monitors process creation and termination
- Command line monitoring
- Executable scanning with YARA
- Process exclusion list

### Network Monitoring
- TCP/UDP connection monitoring
- Process association with network connections
- Port exclusion list
- Suspicious connection detection

### Registry Monitoring
- Registry key change monitoring
- Startup key monitoring
- Value modification tracking
- Process association

## Security Features

- **YARA Integration**: Malware detection using YARA rules
- **File Hashing**: SHA256 hashing of executable files
- **Process Analysis**: Command line and executable analysis
- **Network Analysis**: Connection pattern analysis
- **Registry Analysis**: Startup and persistence mechanism detection

## Logging

Logs are written to `C:\Program Files\EDR-Agent\logs\agent.log` by default.

Log levels:
- `debug`: Detailed debugging information
- `info`: General information
- `warn`: Warning messages
- `error`: Error messages

## Troubleshooting

### Common Issues

1. **Service won't start**
   - Check if running as Administrator
   - Verify config.yaml exists and is valid
   - Check Windows Event Logs

2. **Can't connect to server**
   - Verify server URL in config.yaml
   - Check network connectivity
   - Verify firewall settings

3. **File monitoring not working**
   - Check if paths exist in config.yaml
   - Verify file permissions
   - Check log files for errors

### Debug Mode

Run in console mode for debugging:

```powershell
.\edr-agent.exe -config "config.yaml"
```

## Development

### Building from Source

```powershell
# Install dependencies
go mod tidy

# Build
go build -o edr-agent.exe main.go

# Run tests
go test ./...
```

### Adding New Features

1. **New Monitor**: Add to `internal/monitoring/`
2. **New Scanner**: Add to `internal/scanner/`
3. **Configuration**: Update `internal/config/config.go`
4. **Tests**: Add tests in `_test.go` files

## License

This project is part of the EDR (Endpoint Detection and Response) system. 