package protection

import "time"

type Disposition string

const (
	DispositionClean      Disposition = "clean"
	DispositionUnknown    Disposition = "unknown"
	DispositionSuspicious Disposition = "suspicious"
	DispositionMalicious  Disposition = "malicious"
)

type Signal struct {
	Source        string `json:"source"`
	ID            string `json:"id"`
	Confidence    int    `json:"confidence"`
	Authoritative bool   `json:"authoritative"`
	Detail        string `json:"detail,omitempty"`
}

type Verdict struct {
	ID            string      `json:"id"`
	Path          string      `json:"path"`
	SHA256        string      `json:"sha256"`
	Size          int64       `json:"size"`
	ScannedAt     time.Time   `json:"scanned_at"`
	Score         int         `json:"score"`
	Disposition   Disposition `json:"disposition"`
	Authoritative bool        `json:"authoritative"`
	RuleVersion   string      `json:"rule_version,omitempty"`
	Signals       []Signal    `json:"signals,omitempty"`
	SkippedReason string      `json:"skipped_reason,omitempty"`
}

type ScanSummary struct {
	ID          string    `json:"id"`
	Profile     string    `json:"profile"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Files       int       `json:"files"`
	Skipped     int       `json:"skipped"`
	Suspicious  int       `json:"suspicious"`
	Malicious   int       `json:"malicious"`
	Errors      int       `json:"errors"`
	Running     bool      `json:"running"`
}

type Status struct {
	Enabled           bool          `json:"enabled"`
	Mode              string        `json:"mode"`
	AuditStartedAt    time.Time     `json:"audit_started_at,omitempty"`
	AuditReadyAt      time.Time     `json:"audit_ready_at,omitempty"`
	EnforcementReady  bool          `json:"enforcement_ready"`
	YaraEnabled       bool          `json:"yara_enabled"`
	YaraRuleVersion   string        `json:"yara_rule_version,omitempty"`
	AMSIAvailable     bool          `json:"amsi_available"`
	ReputationEnabled bool          `json:"reputation_enabled"`
	Scans             uint64        `json:"scans"`
	FilesScanned      uint64        `json:"files_scanned"`
	Suspicious        uint64        `json:"suspicious"`
	Malicious         uint64        `json:"malicious"`
	Quarantined       uint64        `json:"quarantined"`
	Killed            uint64        `json:"killed"`
	Errors            uint64        `json:"errors"`
	ScanRunning       bool          `json:"scan_running"`
	CurrentScanID     string        `json:"current_scan_id,omitempty"`
	LastScanAt        *time.Time    `json:"last_scan_at,omitempty"`
	LastScan          *ScanSummary  `json:"last_scan,omitempty"`
	RecentScans       []ScanSummary `json:"recent_scans,omitempty"`
	DegradedReasons   []string      `json:"degraded_reasons,omitempty"`
}
