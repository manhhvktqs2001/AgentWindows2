package communication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func NewServerClient(config config.ServerConfig, logger *utils.Logger) *ServerClient {
	return &ServerClient{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
		},
		logger: logger,
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

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	resp, err := sc.post(url, jsonData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed: %d", resp.StatusCode)
	}

	return nil
}

func (sc *ServerClient) SendEvents(events []interface{}) error {
	url := sc.config.URL + "/api/v1/agents/events"

	jsonData, err := json.Marshal(events)
	if err != nil {
		return err
	}

	resp, err := sc.post(url, jsonData)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("send events failed: %d", resp.StatusCode)
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
