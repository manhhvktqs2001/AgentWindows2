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
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/utils"
)

type ServerClient struct {
	config     config.ServerConfig
	httpClient *http.Client
	logger     *utils.Logger
	agentID    string
}

type HeartbeatData struct {
	AgentID    string                 `json:"agent_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Status     string                 `json:"status"`
	SystemInfo map[string]interface{} `json:"system_info"`
	Metrics    map[string]interface{} `json:"metrics"`
}

// AgentRegistrationRequest với authentication
type AgentRegistrationRequest struct {
	AuthToken    string                 `json:"auth_token"` // Pre-shared token
	Hostname     string                 `json:"hostname"`
	IPAddress    string                 `json:"ip_address"`
	MACAddress   string                 `json:"mac_address"`
	OSType       string                 `json:"os_type"`
	OSVersion    string                 `json:"os_version"`
	Architecture string                 `json:"architecture"`
	AgentVersion string                 `json:"agent_version"`
	SystemInfo   map[string]interface{} `json:"system_info"`
}

// AgentRegistrationResponse từ server
type AgentRegistrationResponse struct {
	Success   bool   `json:"success"`
	AgentID   string `json:"agent_id"`
	APIKey    string `json:"api_key"`
	Message   string `json:"message"`
	ExpiresAt string `json:"expires_at,omitempty"` // Optional: API key expiry
}

type AgentRegistration struct {
	Hostname     string                 `json:"hostname"`
	IPAddress    string                 `json:"ip_address"`
	MACAddress   string                 `json:"mac_address"`
	OSType       string                 `json:"os_type"`
	OSVersion    string                 `json:"os_version"`
	Architecture string                 `json:"architecture"`
	AgentVersion string                 `json:"agent_version"`
	SystemInfo   map[string]interface{} `json:"system_info"`
}

// NewServerClient tạo Server Client mới
func NewServerClient(cfg *config.ServerConfig, logger *utils.Logger) *ServerClient {
	// Tăng timeout cho HTTP client
	httpClient := &http.Client{
		Timeout: time.Duration(cfg.Timeout*2) * time.Second, // Tăng timeout gấp đôi
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	return &ServerClient{
		config:     *cfg,
		logger:     logger,
		httpClient: httpClient,
	}
}

// Register với authentication token
func (sc *ServerClient) Register(registration AgentRegistrationRequest) (*AgentRegistrationResponse, error) {
	url := sc.config.URL + "/api/v1/agents/register"

	// Validate auth token
	if registration.AuthToken == "" {
		return nil, fmt.Errorf("authentication token is required for registration")
	}

	data, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration data: %w", err)
	}

	sc.logger.Info("Attempting agent registration with server")
	sc.logger.Debug("Registration payload size: %d bytes", len(data))

	// Thực hiện request với retry
	var resp *http.Response
	for attempt := 1; attempt <= sc.config.RetryCount; attempt++ {
		resp, err = sc.postWithAuth(url, data, registration.AuthToken)
		if err == nil {
			break
		}

		if attempt < sc.config.RetryCount {
			waitTime := time.Duration(attempt) * time.Second
			sc.logger.Warn("Registration attempt %d failed, retrying in %v: %v", attempt, waitTime, err)
			time.Sleep(waitTime)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to register after %d attempts: %w", sc.config.RetryCount, err)
	}
	defer resp.Body.Close()

	// Đọc response body để logging chi tiết
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result AgentRegistrationResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	// Xử lý các status code khác nhau
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		if !result.Success {
			return nil, fmt.Errorf("registration failed: %s", result.Message)
		}

		sc.agentID = result.AgentID
		if result.APIKey != "" {
			sc.config.APIKey = result.APIKey
			sc.logger.Info("Received API key from server")
		}

		sc.logger.Info("Agent registration successful - ID: %s", result.AgentID)
		return &result, nil

	case http.StatusUnauthorized:
		return nil, fmt.Errorf("authentication failed: invalid auth token")

	case http.StatusConflict:
		return nil, fmt.Errorf("agent already registered: %s", result.Message)

	case http.StatusBadRequest:
		return nil, fmt.Errorf("invalid registration request: %s", result.Message)

	default:
		return nil, fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, result.Message)
	}
}

func (sc *ServerClient) SendHeartbeat(data HeartbeatData) error {
	url := fmt.Sprintf("%s/api/v1/agents/heartbeat", sc.config.URL)

	// If server URL empty or API key missing, skip quietly
	if sc.config.URL == "" || sc.config.APIKey == "" {
		sc.logger.Debug("Skipping heartbeat: server URL or API key not set")
		return nil
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := sc.post(url, jsonData)
	if err != nil {
		sc.logger.Warn("Heartbeat skipped (server unreachable): %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		sc.logger.Warn("Heartbeat not accepted (status %d). Suppressing error.", resp.StatusCode)
		return nil
	}

	return nil
}

func (sc *ServerClient) SendEvents(events []interface{}) error {
	url := sc.config.URL + "/api/v1/agents/events"

	if sc.config.URL == "" || sc.config.APIKey == "" || sc.agentID == "" {
		sc.logger.Debug("Skipping send events: server URL/API key/agentID not set")
		return nil
	}

	jsonData, err := json.Marshal(events)
	if err != nil {
		sc.logger.Error("Failed to marshal events: %v", err)
		return err
	}

	// Retry logic with exponential backoff using configured retry count
	maxRetries := sc.config.RetryCount
	if maxRetries <= 0 {
		maxRetries = 3
	}
	backoff := time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			sc.logger.Error("Failed to create request: %v", err)
			return err
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", sc.config.APIKey)
		req.Header.Set("X-Agent-ID", sc.agentID)

		resp, err := sc.httpClient.Do(req)
		if err != nil {
			if attempt < maxRetries-1 {
				sc.logger.Warn("Send events failed (attempt %d/%d), retrying in %v: %v",
					attempt+1, maxRetries, backoff, err)
				time.Sleep(backoff)
				backoff *= 2 // Exponential backoff
				continue
			}
			sc.logger.Warn("Send events skipped (server unreachable after %d attempts): %v", maxRetries, err)
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			sc.logger.Warn("Send events not accepted: %d, response: %s (suppressed)", resp.StatusCode, string(body))
			return nil
		}

		sc.logger.Info("Sent %d events to server", len(events))
		return nil
	}

	return nil
}

func (sc *ServerClient) GetTasks() ([]interface{}, error) {
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

func (sc *ServerClient) post(url string, data []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", sc.config.APIKey)

	return sc.httpClient.Do(req)
}

// postWithAuth gửi POST request với authentication token
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

// GetAPIKey returns the current API key
func (sc *ServerClient) GetAPIKey() string {
	return sc.config.APIKey
}

// UpdateAPIKey updates the API key in the server client
func (sc *ServerClient) UpdateAPIKey(newAPIKey string) {
	sc.config.APIKey = newAPIKey
	sc.logger.Info("Updated API key in server client: %s", newAPIKey)
}

// SetAgentID sets the agent ID
func (sc *ServerClient) SetAgentID(agentID string) {
	sc.agentID = agentID
	sc.logger.Info("Set agent ID: %s", agentID)
}

// GetAgentID returns the current agent ID
func (sc *ServerClient) GetAgentID() string {
	return sc.agentID
}

// CheckAgentExistsByMAC với auth token
func (sc *ServerClient) CheckAgentExistsByMAC(macAddress string) (bool, string, string, error) {
	url := fmt.Sprintf("%s/api/v1/agents/check-by-mac?mac=%s", sc.config.URL, macAddress)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "", "", err
	}

	req.Header.Set("Content-Type", "application/json")
	// Sử dụng auth token để check (vì đây là operation sensitive)
	if sc.config.AuthToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", sc.config.AuthToken))
	}

	var resp *http.Response
	for attempt := 1; attempt <= sc.config.RetryCount; attempt++ {
		resp, err = sc.httpClient.Do(req)
		if err == nil {
			break
		}
		if attempt < sc.config.RetryCount {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	if err != nil {
		return false, "", "", fmt.Errorf("failed to check agent existence: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Exists  bool   `json:"exists"`
		AgentID string `json:"agent_id,omitempty"`
		APIKey  string `json:"api_key,omitempty"`
		Message string `json:"message,omitempty"`
		Status  string `json:"status,omitempty"`
	}

	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return false, "", "", fmt.Errorf("failed to parse check response: %w", err)
		}
		sc.logger.Info("MAC check result - Exists: %v, Status: %s", result.Exists, result.Status)
		return result.Exists, result.AgentID, result.APIKey, nil

	case http.StatusNotFound:
		// Agent không tồn tại
		return false, "", "", nil

	case http.StatusUnauthorized:
		return false, "", "", fmt.Errorf("unauthorized: invalid auth token")

	default:
		json.NewDecoder(resp.Body).Decode(&result)
		return false, "", "", fmt.Errorf("server returned status %d: %s", resp.StatusCode, result.Message)
	}
}

// SendAlert sends an alert to the server
func (sc *ServerClient) SendAlert(alertData map[string]interface{}) error {
	url := sc.config.URL + "/api/v1/agents/alerts"

	if sc.config.URL == "" || sc.config.APIKey == "" || sc.agentID == "" {
		sc.logger.Debug("Skipping send alert: server URL/API key/agentID not set")
		return nil
	}

	jsonData, err := json.Marshal(alertData)
	if err != nil {
		sc.logger.Error("Failed to marshal alert data: %v", err)
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		sc.logger.Error("Failed to create alert request: %v", err)
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", sc.config.APIKey)
	req.Header.Set("X-Agent-ID", sc.agentID)

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		sc.logger.Warn("Send alert skipped (server unreachable): %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			sc.logger.Warn("Send alert unauthorized (suppressed): %d, response: %s", resp.StatusCode, string(body))
			return nil
		}
		sc.logger.Warn("Send alert not accepted (suppressed): %d, response: %s", resp.StatusCode, string(body))
		return nil
	}

	sc.logger.Info("Alert sent to server successfully")
	return nil
}

// isFileAccessible checks if a file can be accessed for reading
func (sc *ServerClient) isFileAccessible(filePath string) bool {
	// Try to open file with read access
	file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer file.Close()

	// Try to get file info
	_, err = file.Stat()
	return err == nil
}

// waitForFileAccess waits for a file to become accessible
func (sc *ServerClient) waitForFileAccess(filePath string, maxWait time.Duration) bool {
	start := time.Now()
	checkInterval := 100 * time.Millisecond

	for time.Since(start) < maxWait {
		if sc.isFileAccessible(filePath) {
			return true
		}
		time.Sleep(checkInterval)
	}
	return false
}

func (sc *ServerClient) UploadQuarantineFile(agentID string, filePath string) error {
	if sc.config.URL == "" || sc.config.APIKey == "" || agentID == "" {
		sc.logger.Debug("Skipping upload quarantine file: server URL/API key/agentID not set")
		return nil
	}

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		sc.logger.Warn("File does not exist for upload: %s", filePath)
		return fmt.Errorf("file does not exist: %s", filePath)
	}

	// Check if file is accessible
	if !sc.isFileAccessible(filePath) {
		sc.logger.Debug("File not immediately accessible, waiting for access: %s", filePath)

		// Wait up to 10 seconds for file to become accessible
		if !sc.waitForFileAccess(filePath, 10*time.Second) {
			sc.logger.Warn("File not accessible after waiting: %s", filePath)
			return fmt.Errorf("file not accessible for upload: %s", filePath)
		}
	}

	sc.logger.Debug("Starting file upload for: %s", filePath)

	// Try to read file content using multiple strategies
	fileContent, err := sc.readFileWithMultipleStrategies(filePath)
	if err != nil {
		sc.logger.Error("Failed to read file content using all strategies: %v", err)
		return fmt.Errorf("failed to read file content: %w", err)
	}

	// Check if we got any content
	if len(fileContent) == 0 {
		sc.logger.Warn("No content read from file, skipping upload: %s", filePath)
		return fmt.Errorf("no content read from file: %s", filePath)
	}

	sc.logger.Debug("Successfully read %d bytes from file: %s", len(fileContent), filePath)

	// Create a temporary file to use with http.PostForm
	tempFile, err := os.CreateTemp("", "upload_*")
	if err != nil {
		sc.logger.Error("Failed to create temp file: %v", err)
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Write content to temp file
	_, err = tempFile.Write(fileContent)
	if err != nil {
		sc.logger.Error("Failed to write to temp file: %v", err)
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	// Reset file pointer to beginning
	tempFile.Seek(0, 0)

	// Create multipart form data using the temp file
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add agent_id field
	agentField, err := writer.CreateFormField("agent_id")
	if err != nil {
		sc.logger.Error("Failed to create agent_id field: %v", err)
		return fmt.Errorf("failed to create form field: %w", err)
	}
	agentField.Write([]byte(agentID))
	sc.logger.Debug("Added agent_id field: %s", agentID)

	// Add file field
	fileField, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		sc.logger.Error("Failed to create file field: %v", err)
		return fmt.Errorf("failed to create file field: %w", err)
	}

	sc.logger.Debug("Created file field for: %s", filepath.Base(filePath))

	// Copy from temp file to form field
	bytesWritten, err := io.Copy(fileField, tempFile)
	if err != nil {
		sc.logger.Error("Failed to copy file content to form: %v", err)
		return fmt.Errorf("failed to copy file content to form: %w", err)
	}

	sc.logger.Debug("Copied %d bytes to file field", bytesWritten)

	// Close the writer to finalize the multipart data
	writer.Close()
	sc.logger.Debug("Multipart form data created, total size: %d bytes", buffer.Len())
	sc.logger.Debug("Content-Type: %s", writer.FormDataContentType())

	// Create request with the multipart data
	url := sc.config.URL + "/api/v1/public/quarantine/upload"
	req, err := http.NewRequest("POST", url, &buffer)
	if err != nil {
		sc.logger.Error("Failed to create upload request: %v", err)
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", sc.config.APIKey)
	req.Header.Set("X-Agent-ID", agentID)

	sc.logger.Debug("Sending upload request to: %s", url)

	// Send request
	resp, err := sc.httpClient.Do(req)
	if err != nil {
		sc.logger.Warn("Upload quarantine file skipped (server unreachable): %v", err)
		return fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		sc.logger.Error("Failed to read response body: %v", err)
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check response status with special handling for MinIO capacity
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyStr := string(responseBody)
		if resp.StatusCode == http.StatusInternalServerError && (strings.Contains(strings.ToLower(bodyStr), "minio") || strings.Contains(strings.ToLower(bodyStr), "minimum free drive threshold")) {
			sc.logger.Warn("Upload skipped due to storage capacity (MinIO threshold). Please free space. Response: %s", bodyStr)
			return nil
		}
		sc.logger.Warn("Upload quarantine file failed: %d, response: %s", resp.StatusCode, bodyStr)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, bodyStr)
	}

	// Parse response
	var response struct {
		QuarantineID string `json:"quarantine_id"`
		Message      string `json:"message"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		sc.logger.Warn("Failed to parse upload response: %v", err)
		// Don't return error, upload was successful
	}

	sc.logger.Info("✅ File uploaded to server successfully: %s (Quarantine ID: %s)", filepath.Base(filePath), response.QuarantineID)
	return nil
}

// readFileWithMultipleStrategies attempts to read a file using multiple strategies
// to handle Windows-specific file access issues
func (sc *ServerClient) readFileWithMultipleStrategies(filePath string) ([]byte, error) {
	// Strategy 1: Standard file reading with retry
	if content, err := sc.readFileStandard(filePath); err == nil {
		return content, nil
	} else {
		sc.logger.Debug("Standard file reading failed: %v", err)
	}

	// Strategy 2: Chunked reading with Windows error recovery
	if content, err := sc.readFileChunked(filePath); err == nil {
		return content, nil
	} else {
		sc.logger.Debug("Chunked file reading failed: %v", err)
	}

	// Strategy 3: Try to copy to temp file first, then read
	if content, err := sc.readFileViaCopy(filePath); err == nil {
		return content, nil
	} else {
		sc.logger.Debug("File reading via copy failed: %v", err)
	}

	return nil, fmt.Errorf("all file reading strategies failed for: %s", filePath)
}

// readFileStandard attempts standard file reading with retry logic
func (sc *ServerClient) readFileStandard(filePath string) ([]byte, error) {
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		sc.logger.Debug("Standard file reading attempt %d/%d for: %s", attempt, maxRetries, filePath)

		// Try to open file
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
		if err != nil {
			lastErr = err
			sc.logger.Debug("Failed to open file (attempt %d): %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to open file: %w", err)
		}

		// Get file info
		fileInfo, err := file.Stat()
		if err != nil {
			file.Close()
			lastErr = err
			sc.logger.Debug("Failed to get file info (attempt %d): %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to get file info: %w", err)
		}

		fileSize := fileInfo.Size()
		if fileSize == 0 {
			file.Close()
			return []byte{}, nil
		}

		// Read file content
		content := make([]byte, fileSize)
		n, err := file.Read(content)
		file.Close()

		if err != nil && err != io.EOF {
			lastErr = err
			sc.logger.Debug("Failed to read file (attempt %d): %v", attempt, err)
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("failed to read file: %w", err)
		}

		if int64(n) != fileSize {
			sc.logger.Warn("Partial read: expected %d bytes, got %d bytes", fileSize, n)
			content = content[:n]
		}

		sc.logger.Debug("Successfully read %d bytes using standard method", len(content))
		return content, nil
	}

	return nil, fmt.Errorf("all standard reading attempts failed: %w", lastErr)
}

// readFileChunked attempts chunked file reading with Windows error recovery
func (sc *ServerClient) readFileChunked(filePath string) ([]byte, error) {
	sc.logger.Debug("Attempting chunked file reading for: %s", filePath)

	// Get file info first
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	fileSize := fileInfo.Size()
	if fileSize == 0 {
		return []byte{}, nil
	}

	// Try multiple file opening strategies
	var file *os.File
	openStrategies := []struct {
		flags int
		desc  string
	}{
		{os.O_RDONLY, "standard read-only"},
		{os.O_RDONLY | os.O_SYNC, "read-only with sync"},
	}

	for _, strategy := range openStrategies {
		file, err = os.OpenFile(filePath, strategy.flags, 0)
		if err == nil {
			sc.logger.Debug("Successfully opened file with strategy: %s", strategy.desc)
			break
		}
		sc.logger.Debug("Failed to open file with strategy %s: %v", strategy.desc, err)
	}

	if file == nil {
		return nil, fmt.Errorf("failed to open file with any strategy")
	}
	defer file.Close()

	// Read file in chunks with aggressive error recovery
	const chunkSize = 32 * 1024 // 32KB chunks
	content := make([]byte, 0, fileSize)
	totalRead := int64(0)
	consecutiveErrors := 0
	maxConsecutiveErrors := 3

	for totalRead < fileSize {
		// Calculate chunk size for this iteration
		remaining := fileSize - totalRead
		currentChunkSize := chunkSize
		if remaining < int64(chunkSize) {
			currentChunkSize = int(remaining)
		}

		// Read chunk
		chunk := make([]byte, currentChunkSize)
		n, err := file.Read(chunk)

		if n > 0 {
			content = append(content, chunk[:n]...)
			totalRead += int64(n)
			consecutiveErrors = 0 // Reset error counter on successful read
			sc.logger.Debug("Read chunk: %d bytes, total: %d/%d", n, totalRead, fileSize)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			consecutiveErrors++
			sc.logger.Warn("Failed to read chunk at position %d (error %d/%d): %v", totalRead, consecutiveErrors, maxConsecutiveErrors, err)

			// Check if this is a Windows-specific error
			if strings.Contains(err.Error(), "Incorrect function") ||
				strings.Contains(err.Error(), "Access is denied") ||
				strings.Contains(err.Error(), "The process cannot access the file") ||
				strings.Contains(err.Error(), "The file cannot be accessed by the system") {

				sc.logger.Warn("Windows file access error detected, attempting recovery...")

				// Try to recover by closing and reopening the file
				file.Close()
				time.Sleep(500 * time.Millisecond) // Increased wait time

				// Try to reopen with different strategy
				for _, strategy := range openStrategies {
					file, err = os.OpenFile(filePath, strategy.flags, 0)
					if err == nil {
						sc.logger.Debug("Successfully reopened file with strategy: %s", strategy.desc)
						break
					}
				}

				if file == nil {
					sc.logger.Error("Failed to reopen file after error")
					return nil, fmt.Errorf("failed to reopen file after error")
				}

				// Seek to current position
				if _, seekErr := file.Seek(totalRead, 0); seekErr != nil {
					sc.logger.Error("Failed to seek to position %d: %v", totalRead, seekErr)
					return nil, fmt.Errorf("failed to seek in file: %w", seekErr)
				}

				// Continue reading from this position
				continue
			}

			// For other errors, check if we've had too many consecutive errors
			if consecutiveErrors >= maxConsecutiveErrors {
				sc.logger.Error("Too many consecutive errors (%d), giving up", consecutiveErrors)
				if totalRead > 0 && len(content) > 0 {
					sc.logger.Warn("Partial read successful (%d bytes), returning partial content", len(content))
					return content, nil
				}
				return nil, fmt.Errorf("failed to read file after %d consecutive errors: %w", consecutiveErrors, err)
			}

			// Wait before retry for non-Windows errors
			time.Sleep(100 * time.Millisecond)
			continue
		}
	}

	return content, nil
}

// readFileViaCopy attempts to read file by first copying it to a temporary location
func (sc *ServerClient) readFileViaCopy(filePath string) ([]byte, error) {
	sc.logger.Debug("Attempting file reading via copy for: %s", filePath)

	// Create temporary file
	tempFile, err := os.CreateTemp("", "read_copy_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Try to copy the file
	srcFile, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Copy file content
	_, err = io.Copy(tempFile, srcFile)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}

	// Reset temp file pointer
	tempFile.Seek(0, 0)

	// Read from temp file
	content, err := io.ReadAll(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read temp file: %w", err)
	}

	sc.logger.Debug("Successfully read %d bytes via copy method", len(content))
	return content, nil
}

// isWindowsSpecialFile checks if a file might be a special Windows file type
// that could cause "Incorrect function" errors
func (sc *ServerClient) isWindowsSpecialFile(filePath string) bool {
	// Check file extension for known problematic types
	ext := strings.ToLower(filepath.Ext(filePath))
	specialExtensions := []string{
		".lnk",       // Shortcut files
		".url",       // Internet shortcuts
		".pif",       // Program information files
		".scf",       // Shell command files
		".desktop",   // Desktop entry files
		".directory", // Directory entry files
	}

	for _, specialExt := range specialExtensions {
		if ext == specialExt {
			return true
		}
	}

	// Check if file name contains special patterns
	fileName := strings.ToLower(filepath.Base(filePath))
	specialPatterns := []string{
		"thumbs.db",
		"desktop.ini",
		"autorun.inf",
		"ntuser.dat",
		"ntuser.ini",
		"ntuser.pol",
	}

	for _, pattern := range specialPatterns {
		if strings.Contains(fileName, pattern) {
			return true
		}
	}

	return false
}

// readFileWindowsSpecific attempts Windows-specific file reading strategies
func (sc *ServerClient) readFileWindowsSpecific(filePath string) ([]byte, error) {
	sc.logger.Debug("Attempting Windows-specific file reading for: %s", filePath)

	// Check if this might be a special Windows file
	if sc.isWindowsSpecialFile(filePath) {
		sc.logger.Debug("File appears to be a special Windows file type: %s", filePath)

		// For special files, try to read with minimal processing
		// Sometimes these files can be read if we don't try to get their size first
		file, err := os.OpenFile(filePath, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to open special Windows file: %w", err)
		}
		defer file.Close()

		// Read without getting file size first
		content, err := io.ReadAll(file)
		if err == nil {
			sc.logger.Debug("Successfully read special Windows file: %d bytes", len(content))
			return content, nil
		}

		sc.logger.Debug("Failed to read special Windows file: %v", err)
	}

	// Try alternative file access patterns
	accessPatterns := []struct {
		flags int
		desc  string
	}{
		{os.O_RDONLY, "standard read-only"},
		{os.O_RDONLY | os.O_SYNC, "read-only with sync"},
		{os.O_RDONLY | os.O_APPEND, "read-only with append"}, // Sometimes helps with locked files
	}

	for _, pattern := range accessPatterns {
		file, err := os.OpenFile(filePath, pattern.flags, 0)
		if err != nil {
			sc.logger.Debug("Failed to open file with pattern %s: %v", pattern.desc, err)
			continue
		}

		// Try to read the file
		content, err := io.ReadAll(file)
		file.Close()

		if err == nil {
			sc.logger.Debug("Successfully read file with pattern %s: %d bytes", pattern.desc, len(content))
			return content, nil
		}

		sc.logger.Debug("Failed to read file with pattern %s: %v", pattern.desc, err)
	}

	return nil, fmt.Errorf("Windows-specific file reading strategies failed")
}
