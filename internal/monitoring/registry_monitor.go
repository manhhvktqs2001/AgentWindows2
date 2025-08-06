package monitoring

import (
	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type RegistryMonitor struct {
	config    *config.RegistryConfig
	logger    *utils.Logger
	eventChan chan models.RegistryEvent
	stopChan  chan bool
	agentID   string // Add agent ID field
}

func NewRegistryMonitor(cfg *config.RegistryConfig, logger *utils.Logger) *RegistryMonitor {
	return &RegistryMonitor{
		config:    cfg,
		logger:    logger,
		eventChan: make(chan models.RegistryEvent, 1000),
		stopChan:  make(chan bool),
		agentID:   "", // Will be set later
	}
}

func (rm *RegistryMonitor) Start() error {
	rm.logger.Info("Starting registry monitor...")

	// TODO: Implement registry monitoring
	// This would use Windows registry APIs to monitor changes

	rm.logger.Info("Registry monitor started successfully")
	return nil
}

func (rm *RegistryMonitor) Stop() {
	rm.logger.Info("Stopping registry monitor...")
	close(rm.stopChan)
	close(rm.eventChan)
	rm.logger.Info("Registry monitor stopped")
}

func (rm *RegistryMonitor) GetEventChannel() <-chan models.RegistryEvent {
	return rm.eventChan
}

// SetAgentID sets the agent ID for events
func (rm *RegistryMonitor) SetAgentID(agentID string) {
	rm.agentID = agentID
}
