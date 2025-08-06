package communication

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func (sc *ServerClient) Register(registration AgentRegistration) (string, error) {
	url := sc.config.URL + "/api/v1/agents/register"

	data, err := json.Marshal(registration)
	if err != nil {
		return "", err
	}

	resp, err := sc.post(url, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registration failed: %d", resp.StatusCode)
	}

	var result struct {
		AgentID string `json:"agent_id"`
		APIKey  string `json:"api_key"`
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	sc.agentID = result.AgentID

	// Update API key if provided by server
	if result.APIKey != "" {
		sc.config.APIKey = result.APIKey
		sc.logger.Info("Received new API key from server")
	}

	return result.AgentID, nil
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

// GetAPIKey returns the current API key
func (sc *ServerClient) GetAPIKey() string {
	return sc.config.APIKey
}
