package monitoring

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type NetworkMonitor struct {
	config    *config.NetworkConfig
	logger    *utils.Logger
	eventChan chan models.NetworkEvent
	stopChan  chan bool
	agentID   string // Add agent ID field
}

func NewNetworkMonitor(cfg *config.NetworkConfig, logger *utils.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.NetworkEvent, 1000),
		stopChan:  make(chan bool),
		agentID:   "", // Will be set later
	}
}

func (nm *NetworkMonitor) Start() error {
	nm.logger.Info("Starting network monitor...")

	// TODO: Implement network monitoring
	// This would use Windows networking APIs to monitor connections

	nm.logger.Info("Network monitor started successfully")
	return nil
}

func (nm *NetworkMonitor) Stop() {
	nm.logger.Info("Stopping network monitor...")
	close(nm.stopChan)
	close(nm.eventChan)
	nm.logger.Info("Network monitor stopped")
}

func (nm *NetworkMonitor) GetEventChannel() <-chan models.NetworkEvent {
	return nm.eventChan
}

// SetAgentID sets the agent ID for events
func (nm *NetworkMonitor) SetAgentID(agentID string) {
	nm.agentID = agentID
}
