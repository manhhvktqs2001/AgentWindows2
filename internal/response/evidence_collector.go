package response

import (
	"time"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// EvidenceCollector thu thập bằng chứng khi phát hiện threat
type EvidenceCollector struct {
	config *config.ResponseConfig
	logger *utils.Logger
}

// NewEvidenceCollector tạo Evidence Collector mới
func NewEvidenceCollector(cfg *config.ResponseConfig, logger *utils.Logger) *EvidenceCollector {
	return &EvidenceCollector{
		config: cfg,
		logger: logger,
	}
}

// CollectEvidence thu thập bằng chứng cho threat
func (ec *EvidenceCollector) CollectEvidence(threat *models.ThreatInfo) map[string]interface{} {
	ec.logger.Info("Collecting evidence for threat: %s", threat.ThreatName)

	evidence := map[string]interface{}{
		"threat_name":     threat.ThreatName,
		"threat_type":     threat.ThreatType,
		"file_path":       threat.FilePath,
		"process_id":      threat.ProcessID,
		"process_name":    threat.ProcessName,
		"confidence":      threat.Confidence,
		"severity":        threat.Severity,
		"timestamp":       time.Now(),
		"collector_id":    "edr-agent-windows",
		"description":     threat.Description,
		"yara_rules":      threat.YaraRules,
		"mitre_technique": threat.MITRETechnique,
	}

	ec.logger.Info("Evidence collected for threat: %s", threat.ThreatName)
	return evidence
}
