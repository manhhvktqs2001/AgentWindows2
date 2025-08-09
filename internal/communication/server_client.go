package communication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

// ServerClient handles all communication with the server
type ServerClient struct {
	config     config.ServerConfig
	httpClient *http.Client
	logger     *utils.Logger
	agentID    string

	// Rate limiting for log messages
	rateLimiter *LogRateLimiter
}

// LogRateLimiter manages rate limiting for log messages
type LogRateLimiter struct {
	lastLogTime map[string]time.Time
	logCounts   map[string]int
	mu          sync.Mutex
}

// NewLogRateLimiter creates a new log rate limiter
func NewLogRateLimiter() *LogRateLimiter {
	return &LogRateLimiter{
		lastLogTime: make(map[string]time.Time),
		logCounts:   make(map[string]int),
	}
}

// ShouldLog determines if a log message should be displayed
func (lr *LogRateLimiter) ShouldLog(key string, interval time.Duration, maxCount int) bool {
	lr.mu.Lock()
	defer lr.mu.Unlock()

	now := time.Now()
	lastTime, exists := lr.lastLogTime[key]

	// Reset counter if interval has passed
	if !exists || now.Sub(lastTime) >= interval {
		lr.lastLogTime[key] = now
		lr.logCounts[key] = 1
		return true
	}

	// Check if we've exceeded max count within interval
	if lr.logCounts[key] < maxCount {
		lr.logCounts[key]++
		return true
	}

	return false
}

// Request/Response types
type HeartbeatData struct {
	AgentID    string                 `json:"agent_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Status     string                 `json:"status"`
	SystemInfo map[string]interface{} `json:"system_info"`
	Metrics    map[string]interface{} `json:"metrics"`
}

type AgentRegistrationRequest struct {
	AuthToken    string                 `json:"auth_token"`
	Hostname     string                 `json:"hostname"`
	IPAddress    string                 `json:"ip_address"`
	MACAddress   string                 `json:"mac_address"`
	OSType       string                 `json:"os_type"`
	OSVersion    string                 `json:"os_version"`
	Architecture string                 `json:"architecture"`
	AgentVersion string                 `json:"agent_version"`
	SystemInfo   map[string]interface{} `json:"system_info"`
}

type AgentRegistrationResponse struct {
	Success   bool   `json:"success"`
	AgentID   string `json:"agent_id"`
	APIKey    string `json:"api_key"`
	Message   string `json:"message"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// NewServerClient creates a new server client
func NewServerClient(cfg *config.ServerConfig, logger *utils.Logger) *ServerClient {
	// Create HTTP client with optimized settings
	httpClient := &http.Client{
		Timeout: time.Duration(cfg.Timeout) * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableCompression:  false,
		},
	}

	return &ServerClient{
		config:      *cfg,
		logger:      logger,
		httpClient:  httpClient,
		rateLimiter: NewLogRateLimiter(),
	}
}

// logRateLimited logs with rate limiting
func (sc *ServerClient) logRateLimited(level, key string, format string, args ...interface{}) {
	// Different intervals for different log types
	interval := 30 * time.Second
	maxCount := 3

	switch key {
	case "heartbeat_skip", "events_skip", "alert_skip":
		interval = 5 * time.Minute
		maxCount = 1
	case "heartbeat_fail", "events_fail", "alert_fail":
		interval = 1 * time.Minute
		maxCount = 2
	case "windows_file_error":
		interval = 2 * time.Minute
		maxCount = 1
	}

	if !sc.rateLimiter.ShouldLog(key, interval, maxCount) {
		return
	}

	message := fmt.Sprintf(format, args...)
	switch level {
	case "DEBUG":
		sc.logger.Debug(message)
	case "INFO":
		sc.logger.Info(message)
	case "WARN":
		sc.logger.Warn(message)
	case "ERROR":
		sc.logger.Error(message)
	}
}

// Register registers the agent with the server
func (sc *ServerClient) Register(registration AgentRegistrationRequest) (*AgentRegistrationResponse, error) {
	url := sc.config.URL + "/api/v1/agents/register"

	if registration.AuthToken == "" {
		return nil, fmt.Errorf("authentication token is required")
	}

	data, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %w", err)
	}

	sc.logger.Info("Attempting agent registration with server")

	// Retry logic with exponential backoff
	var resp *http.Response
	maxRetries := sc.config.RetryCount
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = sc.postWithAuth(url, data, registration.AuthToken)
		if err == nil {
			break
		}

		if attempt < maxRetries {
			backoff := time.Duration(attempt*attempt) * time.Second
			sc.logger.Warn("Registration attempt %d/%d failed, retrying in %v", attempt, maxRetries, backoff)
			time.Sleep(backoff)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("registration failed after %d attempts: %w", maxRetries, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var result AgentRegistrationResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Handle different status codes
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		if !result.Success {
			return nil, fmt.Errorf("registration failed: %s", result.Message)
		}
		sc.agentID = result.AgentID
		if result.APIKey != "" {
			sc.config.APIKey = result.APIKey
		}
		sc.logger.Info("Agent registered successfully - ID: %s", result.AgentID)
		return &result, nil

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("unauthorized: invalid auth token")
	case http.StatusConflict:
		return nil, fmt.Errorf("agent already registered: %s", result.Message)
	default:
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, result.Message)
	}
}

// SendHeartbeat sends a heartbeat to the server
func (sc *ServerClient) SendHeartbeat(data HeartbeatData) error {
	if sc.config.URL == "" || sc.config.APIKey == "" {
		sc.logRateLimited("DEBUG", "heartbeat_skip", "Skipping heartbeat: server not configured")
		return nil
	}

	url := fmt.Sprintf("%s/api/v1/agents/heartbeat", sc.config.URL)
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := sc.post(url, jsonData)
	if err != nil {
		sc.logRateLimited("WARN", "heartbeat_fail", "Heartbeat failed: %v", err)
		return nil // Don't propagate error to avoid breaking the agent
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sc.logRateLimited("WARN", "heartbeat_reject", "Heartbeat rejected: status %d", resp.StatusCode)
		return nil
	}

	return nil
}

// SendEvents sends events to the server
func (sc *ServerClient) SendEvents(events []interface{}) error {
	if sc.config.URL == "" || sc.config.APIKey == "" || sc.agentID == "" {
		sc.logRateLimited("DEBUG", "events_skip", "Skipping events: server not configured")
		return nil
	}

	url := sc.config.URL + "/api/v1/agents/events"
	jsonData, err := json.Marshal(events)
	if err != nil {
		sc.logger.Error("Failed to marshal events: %v", err)
		return err
	}

	// Send with retry
	err = sc.postWithRetry(url, jsonData, "events")
	if err != nil {
		sc.logRateLimited("WARN", "events_fail", "Failed to send events: %v", err)
		return nil // Don't propagate error
	}

	sc.logRateLimited("INFO", "events_success", "Sent %d events to server", len(events))
	return nil
}

// SendAlert sends an alert to the server
func (sc *ServerClient) SendAlert(alertData map[string]interface{}) error {
	if sc.config.URL == "" || sc.config.APIKey == "" || sc.agentID == "" {
		sc.logRateLimited("DEBUG", "alert_skip", "Skipping alert: server not configured")
		return nil
	}

	url := sc.config.URL + "/api/v1/agents/alerts"
	jsonData, err := json.Marshal(alertData)
	if err != nil {
		sc.logger.Error("Failed to marshal alert: %v", err)
		return err
	}

	// Send with retry
	err = sc.postWithRetry(url, jsonData, "alert")
	if err != nil {
		sc.logRateLimited("WARN", "alert_fail", "Failed to send alert: %v", err)
		return nil
	}

	sc.logRateLimited("INFO", "alert_success", "Alert sent successfully")
	return nil
}

// UploadQuarantineFile uploads a quarantined file to the server
func (sc *ServerClient) UploadQuarantineFile(agentID string, filePath string) error {
	if sc.config.URL == "" || sc.config.APIKey == "" || agentID == "" {
		sc.logRateLimited("DEBUG", "upload_skip", "Skipping upload: server not configured")
		return nil
	}

	// Check file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			sc.logger.Warn("File does not exist for upload: %s", filePath)
			return nil
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}

	// Skip directories and non-regular files (avoid Windows 'Incorrect function' on special files)
	if fileInfo.IsDir() {
		sc.logRateLimited("INFO", "upload_skip_dir", "Skipping upload of directory: %s", filePath)
		return nil
	}
	if !fileInfo.Mode().IsRegular() {
		sc.logRateLimited("INFO", "upload_skip_special", "Skipping upload of non-regular file: %s", filePath)
		return nil
	}

	// Skip empty files
	if fileInfo.Size() == 0 {
		sc.logger.Warn("Skipping upload of empty file: %s", filePath)
		return nil
	}

	sc.logger.Debug("Starting file upload: %s (%d bytes)", filePath, fileInfo.Size())

	// Read file with optimized strategy
	fileContent, err := sc.readFileOptimized(filePath, fileInfo.Size())
	if err != nil {
		sc.logger.Error("Failed to read file for upload: %v", err)
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create multipart form
	body, contentType, err := sc.createMultipartForm(agentID, filepath.Base(filePath), fileContent)
	if err != nil {
		return fmt.Errorf("failed to create multipart form: %w", err)
	}

	// Upload with retry
	url := sc.config.URL + "/api/v1/public/quarantine/upload"
	err = sc.uploadWithRetry(url, body, contentType)
	if err != nil {
		// Special handling for storage capacity errors
		if strings.Contains(err.Error(), "minio") || strings.Contains(err.Error(), "storage") {
			sc.logger.Warn("Upload skipped due to storage capacity issue")
			return nil
		}
		return fmt.Errorf("upload failed: %w", err)
	}

	sc.logger.Info("✅ File uploaded successfully: %s", filepath.Base(filePath))
	return nil
}

// readFileOptimized reads a file using the most appropriate strategy
func (sc *ServerClient) readFileOptimized(filePath string, fileSize int64) ([]byte, error) {
	// For small files, use simple read
	if fileSize < 1024*1024 { // < 1MB
		return os.ReadFile(filePath)
	}

	// For larger files, use chunked reading
	return sc.readFileChunked(filePath, fileSize)
}

// readFileChunked reads a file in chunks to handle large files and Windows issues
func (sc *ServerClient) readFileChunked(filePath string, fileSize int64) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	const chunkSize = 64 * 1024 // 64KB chunks
	buffer := make([]byte, 0, fileSize)
	chunk := make([]byte, chunkSize)
	totalRead := int64(0)

	for totalRead < fileSize {
		n, err := file.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			totalRead += int64(n)
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			// Handle Windows-specific errors
			if strings.Contains(err.Error(), "Incorrect function") {
				sc.logRateLimited("WARN", "windows_file_error", "Windows file read error, attempting recovery")
				// Try to continue reading
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("read error at byte %d: %w", totalRead, err)
		}
	}

	return buffer, nil
}

// createMultipartForm creates a multipart form for file upload
func (sc *ServerClient) createMultipartForm(agentID, fileName string, fileContent []byte) (*bytes.Buffer, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add agent_id field
	if err := writer.WriteField("agent_id", agentID); err != nil {
		return nil, "", err
	}

	// Add file field
	part, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		return nil, "", err
	}

	if _, err := part.Write(fileContent); err != nil {
		return nil, "", err
	}

	if err := writer.Close(); err != nil {
		return nil, "", err
	}

	return body, writer.FormDataContentType(), nil
}

// postWithRetry sends a POST request with retry logic
func (sc *ServerClient) postWithRetry(url string, data []byte, operation string) error {
	maxRetries := sc.config.RetryCount
	if maxRetries <= 0 {
		maxRetries = 3
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", sc.config.APIKey)
		req.Header.Set("X-Agent-ID", sc.agentID)

		resp, err := sc.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries {
				backoff := time.Duration(attempt*attempt) * time.Second
				sc.logRateLimited("DEBUG", operation+"_retry",
					"Retry %d/%d for %s in %v", attempt, maxRetries, operation, backoff)
				time.Sleep(backoff)
				continue
			}
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			return nil
		}

		// Don't retry on client errors
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server rejected %s: %d - %s", operation, resp.StatusCode, string(body))
		}

		// Retry on server errors
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("%s failed after %d attempts", operation, maxRetries)
}

// uploadWithRetry uploads with retry logic
func (sc *ServerClient) uploadWithRetry(url string, body *bytes.Buffer, contentType string) error {
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Create new reader for each attempt
		bodyReader := bytes.NewReader(body.Bytes())

		req, err := http.NewRequest("POST", url, bodyReader)
		if err != nil {
			return err
		}

		req.Header.Set("Content-Type", contentType)
		req.Header.Set("X-API-Key", sc.config.APIKey)
		req.Header.Set("X-Agent-ID", sc.agentID)

		resp, err := sc.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			return nil
		}

		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("upload rejected: %d - %s", resp.StatusCode, string(respBody))
		}

		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return fmt.Errorf("upload failed after %d attempts", maxRetries)
}

// Helper methods for basic HTTP operations
func (sc *ServerClient) post(url string, data []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", sc.config.APIKey)

	return sc.httpClient.Do(req)
}

func (sc *ServerClient) postWithAuth(url string, data []byte, authToken string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	req.Header.Set("User-Agent", "EDR-Agent/1.0.0")

	return sc.httpClient.Do(req)
}

// CheckAgentExistsByMAC checks if an agent exists by MAC address
func (sc *ServerClient) CheckAgentExistsByMAC(macAddress string) (bool, string, string, error) {
	url := fmt.Sprintf("%s/api/v1/agents/check-by-mac?mac=%s", sc.config.URL, macAddress)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "", "", err
	}

	req.Header.Set("Content-Type", "application/json")
	if sc.config.AuthToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sc.config.AuthToken))
	}

	// Retry logic
	var resp *http.Response
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = sc.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < maxRetries {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	if err != nil {
		return false, "", "", fmt.Errorf("failed to check agent: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Exists  bool   `json:"exists"`
		AgentID string `json:"agent_id,omitempty"`
		APIKey  string `json:"api_key,omitempty"`
		Message string `json:"message,omitempty"`
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, "", "", fmt.Errorf("failed to parse response: %w", err)
		}
		sc.logger.Info("MAC check result - Exists: %v", result.Exists)
		return result.Exists, result.AgentID, result.APIKey, nil

	case http.StatusNotFound:
		return false, "", "", nil

	case http.StatusUnauthorized:
		return false, "", "", fmt.Errorf("unauthorized")

	default:
		return false, "", "", fmt.Errorf("server returned status %d", resp.StatusCode)
	}
}

// GetTasks gets tasks from the server
func (sc *ServerClient) GetTasks() ([]interface{}, error) {
	if sc.config.URL == "" || sc.agentID == "" {
		return nil, fmt.Errorf("server not configured")
	}

	url := fmt.Sprintf("%s/api/v1/agents/%s/tasks", sc.config.URL, sc.agentID)

	resp, err := sc.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get tasks failed: %d", resp.StatusCode)
	}

	var tasks []interface{}
	err = json.NewDecoder(resp.Body).Decode(&tasks)
	return tasks, err
}

// Getter and setter methods
func (sc *ServerClient) GetAPIKey() string {
	return sc.config.APIKey
}

func (sc *ServerClient) UpdateAPIKey(newAPIKey string) {
	sc.config.APIKey = newAPIKey
	sc.logger.Info("API key updated")
}

func (sc *ServerClient) SetAgentID(agentID string) {
	sc.agentID = agentID
	sc.logger.Info("Agent ID set: %s", agentID)
}

func (sc *ServerClient) GetAgentID() string {
	return sc.agentID
}
