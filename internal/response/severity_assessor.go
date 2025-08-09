package response

import (
	"strings"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

// SeverityAssessor đánh giá mức độ nghiêm trọng của threat
type SeverityAssessor struct {
	config *config.ResponseConfig
	logger *utils.Logger

	// Severity mapping rules
	malwareFamilies map[string]int
	threatTypes     map[string]int
	fileExtensions  map[string]int
	processNames    map[string]int
}

// NewSeverityAssessor tạo Severity Assessor mới
func NewSeverityAssessor(cfg *config.ResponseConfig, logger *utils.Logger) *SeverityAssessor {
	sa := &SeverityAssessor{
		config:          cfg,
		logger:          logger,
		malwareFamilies: make(map[string]int),
		threatTypes:     make(map[string]int),
		fileExtensions:  make(map[string]int),
		processNames:    make(map[string]int),
	}

	// Initialize severity mappings
	sa.initializeSeverityMappings()

	return sa
}

// initializeSeverityMappings khởi tạo các mapping severity
func (sa *SeverityAssessor) initializeSeverityMappings() {
	// Malware families severity mapping
	sa.malwareFamilies = map[string]int{
		"trojan":     4,
		"ransomware": 5,
		"backdoor":   5,
		"keylogger":  4,
		"spyware":    4,
		"adware":     3,
		"pup":        2,
		"worm":       4,
		"virus":      4,
		"rootkit":    5,
		"apt":        5,
		"exploit":    5,
		"shellcode":  5,
		"dropper":    4,
		"loader":     4,
		"stealer":    4,
		"miner":      3,
		"generic":    3,
	}

	// Threat types severity mapping
	sa.threatTypes = map[string]int{
		"malware":              4,
		"phishing":             3,
		"exploit":              5,
		"backdoor":             5,
		"data_theft":           4,
		"system_compromise":    5,
		"network_attack":       4,
		"privilege_escalation": 5,
		"persistence":          4,
		"lateral_movement":     4,
		"data_destruction":     5,
		"suspicious":           3,
		"unknown":              2,
	}

	// File extensions severity mapping
	sa.fileExtensions = map[string]int{
		".exe": 3,
		".dll": 3,
		".sys": 4,
		".scr": 4,
		".bat": 3,
		".cmd": 3,
		".ps1": 4,
		".vbs": 4,
		".js":  3,
		".jar": 3,
		".msi": 3,
		".com": 4,
		".pif": 4,
		".lnk": 3,
		".reg": 3,
		".inf": 3,
		".tmp": 1,
		".log": 1,
		".txt": 1,
	}

	// Process names severity mapping
	sa.processNames = map[string]int{
		"cmd.exe":        2,
		"powershell.exe": 3,
		"wscript.exe":    3,
		"cscript.exe":    3,
		"rundll32.exe":   3,
		"regsvr32.exe":   3,
		"mshta.exe":      4,
		"certutil.exe":   3,
		"bitsadmin.exe":  3,
		"wmic.exe":       3,
		"schtasks.exe":   3,
		"at.exe":         3,
		"sc.exe":         3,
		"net.exe":        2,
		"netstat.exe":    1,
		"tasklist.exe":   1,
		"ipconfig.exe":   1,
		"ping.exe":       1,
		"tracert.exe":    1,
		"nslookup.exe":   1,
	}
}

// AssessSeverity đánh giá mức độ nghiêm trọng của threat
func (sa *SeverityAssessor) AssessSeverity(threat *models.ThreatInfo) int {
	sa.logger.Debug("Assessing severity for threat: %s", threat.ThreatName)

	// Start with base severity from threat info
	severity := threat.Severity
	if severity == 0 {
		severity = 3 // Default medium severity
	}

	// Clamp severity for known benign/environmental detections (anti-debug/vm)
	tn := strings.ToLower(threat.ThreatName)
	if strings.Contains(tn, "vmdetect") ||
		strings.Contains(tn, "anti_dbg") ||
		strings.Contains(tn, "debuggercheck") ||
		strings.Contains(tn, "debuggerexception") ||
		strings.Contains(tn, "threadcontrol") ||
		strings.Contains(tn, "seh__vectored") ||
		strings.Contains(tn, "check_outputdebugstringa") {
		// Cap to LOW to avoid auto-quarantine/emergency for environment rules
		severity = 1
	}

	// Factor 1: Malware family analysis
	familySeverity := sa.assessMalwareFamily(threat.ThreatName)
	if familySeverity > severity {
		severity = familySeverity
	}

	// Factor 2: Threat type analysis
	typeSeverity := sa.assessThreatType(threat.ThreatType)
	if typeSeverity > severity {
		severity = typeSeverity
	}

	// Factor 3: File extension analysis
	extSeverity := sa.assessFileExtension(threat.FilePath)
	if extSeverity > severity {
		severity = extSeverity
	}

	// Factor 4: Process name analysis
	processSeverity := sa.assessProcessName(threat.ProcessName)
	if processSeverity > severity {
		severity = processSeverity
	}

	// Factor 5: Confidence score adjustment
	severity = sa.adjustByConfidence(severity, threat.Confidence)

	// Factor 6: MITRE technique analysis
	mitreSeverity := sa.assessMITRETechnique(threat.MITRETechnique)
	if mitreSeverity > severity {
		severity = mitreSeverity
	}

	// Ensure severity is within valid range (1-5)
	if severity < 1 {
		severity = 1
	} else if severity > 5 {
		severity = 5
	}

	sa.logger.Info("Severity assessment: %s -> Level %d", threat.ThreatName, severity)
	return severity
}

// assessMalwareFamily đánh giá severity dựa trên malware family
func (sa *SeverityAssessor) assessMalwareFamily(threatName string) int {
	threatNameLower := strings.ToLower(threatName)

	for family, severity := range sa.malwareFamilies {
		if strings.Contains(threatNameLower, family) {
			sa.logger.Debug("Malware family match: %s -> severity %d", family, severity)
			return severity
		}
	}

	return 3 // Default medium severity
}

// assessThreatType đánh giá severity dựa trên threat type
func (sa *SeverityAssessor) assessThreatType(threatType string) int {
	if severity, exists := sa.threatTypes[strings.ToLower(threatType)]; exists {
		sa.logger.Debug("Threat type match: %s -> severity %d", threatType, severity)
		return severity
	}

	return 3 // Default medium severity
}

// assessFileExtension đánh giá severity dựa trên file extension
func (sa *SeverityAssessor) assessFileExtension(filePath string) int {
	// Extract file extension
	lastDot := strings.LastIndex(filePath, ".")
	if lastDot == -1 {
		return 2 // No extension, low severity
	}

	extension := strings.ToLower(filePath[lastDot:])

	if severity, exists := sa.fileExtensions[extension]; exists {
		sa.logger.Debug("File extension match: %s -> severity %d", extension, severity)
		return severity
	}

	return 2 // Unknown extension, low severity
}

// assessProcessName đánh giá severity dựa trên process name
func (sa *SeverityAssessor) assessProcessName(processName string) int {
	processNameLower := strings.ToLower(processName)

	if severity, exists := sa.processNames[processNameLower]; exists {
		sa.logger.Debug("Process name match: %s -> severity %d", processName, severity)
		return severity
	}

	return 2 // Unknown process, low severity
}

// assessMITRETechnique đánh giá severity dựa trên MITRE technique
func (sa *SeverityAssessor) assessMITRETechnique(technique string) int {
	if technique == "" {
		return 3 // No MITRE technique, medium severity
	}

	techniqueLower := strings.ToLower(technique)

	// High severity MITRE techniques
	highSeverityTechniques := []string{
		"t1055", // Process Injection
		"t1053", // Scheduled Task/Job
		"t1050", // New Service
		"t1037", // Boot or Logon Initialization Scripts
		"t1036", // Masquerading
		"t1027", // Obfuscated Files or Information
		"t1021", // Remote Services
		"t1018", // Remote System Discovery
		"t1016", // System Network Configuration Discovery
		"t1012", // Query Registry
		"t1003", // OS Credential Dumping
		"t1001", // Data Obfuscation
	}

	// Critical severity MITRE techniques
	criticalSeverityTechniques := []string{
		"t1059", // Command and Scripting Interpreter
		"t1053", // Scheduled Task/Job
		"t1031", // Modify System Image
		"t1027", // Obfuscated Files or Information
		"t1018", // Remote System Discovery
		"t1003", // OS Credential Dumping
		"t1001", // Data Obfuscation
		"t1000", // Data Encrypted
	}

	for _, tech := range criticalSeverityTechniques {
		if strings.Contains(techniqueLower, tech) {
			sa.logger.Debug("Critical MITRE technique match: %s", tech)
			return 5
		}
	}

	for _, tech := range highSeverityTechniques {
		if strings.Contains(techniqueLower, tech) {
			sa.logger.Debug("High severity MITRE technique match: %s", tech)
			return 4
		}
	}

	return 3 // Default medium severity for MITRE techniques
}

// adjustByConfidence điều chỉnh severity dựa trên confidence score
func (sa *SeverityAssessor) adjustByConfidence(severity int, confidence float64) int {
	if confidence >= 0.9 {
		// High confidence: increase severity by 1
		if severity < 5 {
			severity++
		}
	} else if confidence <= 0.5 {
		// Low confidence: decrease severity by 1
		if severity > 1 {
			severity--
		}
	}

	return severity
}

// GetSeverityDescription trả về mô tả severity level
func (sa *SeverityAssessor) GetSeverityDescription(severity int) string {
	switch severity {
	case 1:
		return "Low - Suspicious activity detected"
	case 2:
		return "Low-Medium - Potentially unwanted behavior"
	case 3:
		return "Medium - Suspicious file or process"
	case 4:
		return "High - Malicious activity detected"
	case 5:
		return "Critical - Active threat detected"
	default:
		return "Unknown severity level"
	}
}

// GetSeverityColor trả về màu sắc cho severity level
func (sa *SeverityAssessor) GetSeverityColor(severity int) string {
	switch severity {
	case 1, 2:
		return "yellow"
	case 3:
		return "orange"
	case 4:
		return "red"
	case 5:
		return "darkred"
	default:
		return "gray"
	}
}

// GetRecommendedAction trả về hành động được khuyến nghị
func (sa *SeverityAssessor) GetRecommendedAction(severity int) string {
	switch severity {
	case 1, 2:
		return "Monitor and log for analysis"
	case 3:
		return "Prompt user for decision"
	case 4:
		return "Automatically quarantine file"
	case 5:
		return "Emergency response - isolate system"
	default:
		return "Unknown action"
	}
}
