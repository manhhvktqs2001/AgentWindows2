package response

import (
	"strings"

	"edr-agent-windows/internal/config"
	"edr-agent-windows/internal/models"
	"edr-agent-windows/internal/utils"
)

type SeverityAssessor struct {
	config *config.ResponseConfig
	logger *utils.Logger

	// Enhanced mapping rules
	malwareFamilies    map[string]int
	threatTypes        map[string]int
	fileExtensions     map[string]int
	processNames       map[string]int
	environmentalRules map[string]bool
	systemPaths        []string
}

func NewSeverityAssessor(cfg *config.ResponseConfig, logger *utils.Logger) *SeverityAssessor {
	sa := &SeverityAssessor{
		config:             cfg,
		logger:             logger,
		malwareFamilies:    make(map[string]int),
		threatTypes:        make(map[string]int),
		fileExtensions:     make(map[string]int),
		processNames:       make(map[string]int),
		environmentalRules: make(map[string]bool),
	}

	sa.initializeSeverityMappings()
	return sa
}

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

	// Environmental/anti-debug rules that should be de-emphasized
	sa.environmentalRules = map[string]bool{
		"debuggercheck":            true,
		"debuggerexception":        true,
		"debuggerhiding":           true,
		"vmdetect":                 true,
		"anti_dbg":                 true,
		"threadcontrol":            true,
		"seh__vectored":            true,
		"check_outputdebugstringa": true,
		"queryinfo":                true,
		"win_hook":                 true,
		"disable_antivirus":        true,
		"disable_dep":              true,
		"setconsole":               true,
		"setconsolectrl":           true,
		"powershell":               true,
		"capabilities":             true,
		"antisandbox":              true,
		"antivm":                   true,
		"antidebug":                true,
		"antiemulatue":             true,
		"antianalysis":             true,
	}

	// System paths that commonly trigger environmental detections
	sa.systemPaths = []string{
		"\\windows\\system32\\",
		"\\windows\\syswow64\\",
		"\\windows\\winsxs\\",
		"\\program files\\",
		"\\program files (x86)\\",
		"\\programdata\\microsoft\\",
		"edgewebview",
		"microsoft\\edge",
		"windowspowershell",
		"\\quarantine\\",
		"\\.git\\",
		"\\node_modules\\",
		"cursor\\user\\workspacestorage",
		"globalstorage",
		"anysphere.cursor",
	}
}

func (sa *SeverityAssessor) AssessSeverity(threat *models.ThreatInfo) int {
	sa.logger.Debug("Assessing severity for threat: %s", threat.ThreatName)

	// Start with base severity
	severity := threat.Severity
	if severity == 0 {
		severity = 3 // Default medium severity
	}

	// CRITICAL: Apply environmental rule suppression FIRST
	if sa.isEnvironmentalDetection(threat) {
		// Environmental detections on system paths get very low severity
		severity = 1
		sa.logger.Debug("Environmental detection on system path, setting severity to 1: %s", threat.ThreatName)
		return severity
	}

	// Apply other assessment factors only for non-environmental detections

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

	// Final adjustment for system paths (reduce by 1 level)
	if sa.isSystemPath(threat.FilePath) {
		if severity > 1 {
			severity--
		}
		sa.logger.Debug("System path detected, reducing severity by 1: %s", threat.FilePath)
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

func (sa *SeverityAssessor) isEnvironmentalDetection(threat *models.ThreatInfo) bool {
	threatNameLower := strings.ToLower(threat.ThreatName)

	// Check if rule name matches environmental patterns
	for envRule := range sa.environmentalRules {
		if strings.Contains(threatNameLower, envRule) {
			// Check if it's on a system path
			if sa.isSystemPath(threat.FilePath) {
				return true
			}
		}
	}

	return false
}

func (sa *SeverityAssessor) isSystemPath(filePath string) bool {
	if filePath == "" {
		return false
	}

	lowerPath := strings.ToLower(filePath)

	for _, sysPath := range sa.systemPaths {
		if strings.Contains(lowerPath, strings.ToLower(sysPath)) {
			return true
		}
	}

	return false
}

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

func (sa *SeverityAssessor) assessThreatType(threatType string) int {
	if severity, exists := sa.threatTypes[strings.ToLower(threatType)]; exists {
		sa.logger.Debug("Threat type match: %s -> severity %d", threatType, severity)
		return severity
	}

	return 3 // Default medium severity
}

func (sa *SeverityAssessor) assessFileExtension(filePath string) int {
	if filePath == "" {
		return 2
	}

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

func (sa *SeverityAssessor) assessProcessName(processName string) int {
	if processName == "" {
		return 2
	}

	processNameLower := strings.ToLower(processName)

	if severity, exists := sa.processNames[processNameLower]; exists {
		sa.logger.Debug("Process name match: %s -> severity %d", processName, severity)
		return severity
	}

	return 2 // Unknown process, low severity
}

func (sa *SeverityAssessor) assessMITRETechnique(technique string) int {
	if technique == "" {
		return 3 // No MITRE technique, medium severity
	}

	techniqueLower := strings.ToLower(technique)

	// Critical severity MITRE techniques
	criticalSeverityTechniques := []string{
		"t1059", // Command and Scripting Interpreter
		"t1055", // Process Injection
		"t1053", // Scheduled Task/Job
		"t1031", // Modify System Image
		"t1027", // Obfuscated Files or Information
		"t1003", // OS Credential Dumping
		"t1000", // Data Encrypted
	}

	// High severity MITRE techniques
	highSeverityTechniques := []string{
		"t1050", // New Service
		"t1037", // Boot or Logon Initialization Scripts
		"t1036", // Masquerading
		"t1021", // Remote Services
		"t1018", // Remote System Discovery
		"t1016", // System Network Configuration Discovery
		"t1012", // Query Registry
		"t1001", // Data Obfuscation
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

func (sa *SeverityAssessor) GetSeverityDescription(severity int) string {
	switch severity {
	case 1:
		return "Low - Environmental/Informational detection"
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

func (sa *SeverityAssessor) GetSeverityColor(severity int) string {
	switch severity {
	case 1:
		return "lightgray"
	case 2:
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

func (sa *SeverityAssessor) GetRecommendedAction(severity int) string {
	switch severity {
	case 1:
		return "Monitor only - likely false positive"
	case 2:
		return "Log and analyze - low priority"
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

// GetEnvironmentalRules returns the list of environmental rules
func (sa *SeverityAssessor) GetEnvironmentalRules() map[string]bool {
	return sa.environmentalRules
}

// IsEnvironmentalRule checks if a rule name is environmental
func (sa *SeverityAssessor) IsEnvironmentalRule(ruleName string) bool {
	ruleNameLower := strings.ToLower(ruleName)
	for envRule := range sa.environmentalRules {
		if strings.Contains(ruleNameLower, envRule) {
			return true
		}
	}
	return false
}
