package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

var (
	nativeSourceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	windowsChannelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/ -]{0,127}$`)
)

type Source struct {
	ID        string           `json:"id"`
	Enabled   bool             `json:"enabled"`
	Path      string           `json:"path"`
	Format    string           `json:"format"`
	Trust     model.TrustLevel `json:"trust"`
	FromStart bool             `json:"from_start"`
	MaxBatch  int              `json:"max_batch"`
}

type NativeSource struct {
	ID                  string   `json:"id"`
	Enabled             bool     `json:"enabled"`
	Kind                string   `json:"kind"`
	Channel             string   `json:"channel,omitempty"`
	EventIDs            []int    `json:"event_ids,omitempty"`
	Units               []string `json:"units,omitempty"`
	Identifiers         []string `json:"identifiers,omitempty"`
	Path                string   `json:"path,omitempty"`
	FromStart           bool     `json:"from_start"`
	MaxBatch            int      `json:"max_batch"`
	CommandTimeout      string   `json:"command_timeout"`
	MaxActiveSerials    int      `json:"max_active_serials,omitempty"`
	MaxRecordsPerSerial int      `json:"max_records_per_serial,omitempty"`
	MaxBytesPerSerial   int      `json:"max_bytes_per_serial,omitempty"`
	AssemblyTimeout     string   `json:"assembly_timeout,omitempty"`
}

type API struct {
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen"`
	TokenFile string `json:"token_file"`
}

type Central struct {
	Enabled                         bool   `json:"enabled"`
	URL                             string `json:"url"`
	EnrollmentTokenFile             string `json:"enrollment_token_file"`
	APIKeyFile                      string `json:"api_key_file"`
	AllowUntrustedServerCertificate bool   `json:"allow_untrusted_server_certificate"`
	HeartbeatInterval               string `json:"heartbeat_interval"`
	BatchInterval                   string `json:"batch_interval"`
	MaxBatch                        int    `json:"max_batch"`
	QueueSize                       int    `json:"queue_size"`
}

type ToolPolicy struct {
	PolicyFile   string   `json:"policy_file"`
	AllowedPaths []string `json:"allowed_paths"`
}

type AI struct {
	Enabled         bool           `json:"enabled"`
	Endpoint        string         `json:"endpoint"`
	Model           string         `json:"model"`
	APIKeyEnv       string         `json:"api_key_env"`
	APIKeyFile      string         `json:"api_key_file,omitempty"`
	AllowRemote     bool           `json:"allow_remote"`
	Timeout         string         `json:"timeout"`
	AutoAnalyze     bool           `json:"auto_analyze"`
	MinimumSeverity model.Severity `json:"minimum_severity"`
	QueueSize       int            `json:"queue_size"`
	MinInterval     string         `json:"min_interval"`
	AuditLogFile    string         `json:"audit_log_file"`
}

type Inventory struct {
	Enabled          bool   `json:"enabled"`
	Interval         string `json:"interval"`
	CommandTimeout   string `json:"command_timeout"`
	IncludeProcesses bool   `json:"include_processes"`
	IncludeServices  bool   `json:"include_services"`
	IncludeListeners bool   `json:"include_listeners"`
	IncludeSoftware  bool   `json:"include_software"`
	MaxItems         int    `json:"max_items"`
}

// ProcessGraph controls the local Linux-only /proc reconciliation loop. It is
// telemetry only: values here cannot authorize response actions or load code.
type ProcessGraph struct {
	Enabled                bool   `json:"enabled"`
	ReconcileInterval      string `json:"reconcile_interval"`
	MaxProcesses           int    `json:"max_processes"`
	MaxExitedProcesses     int    `json:"max_exited_processes"`
	MaxCommandLineBytes    int    `json:"max_command_line_bytes"`
	MaxExecutableHashBytes int64  `json:"max_executable_hash_bytes"`
}

// ProcessNetwork controls the Linux-only socket-to-process attribution loop.
// It reads fixed /proc files locally and cannot accept remote filters, paths,
// programs, or response requests.
type ProcessNetwork struct {
	Enabled            bool   `json:"enabled"`
	ReconcileInterval  string `json:"reconcile_interval"`
	MaxProcesses       int    `json:"max_processes"`
	MaxSockets         int    `json:"max_sockets"`
	MaxFileDescriptors int    `json:"max_file_descriptors"`
}

// EBPFSensor controls the fixed, embedded Linux CO-RE sensor. These local
// limits cannot install a caller-provided program or filter.
type EBPFSensor struct {
	Enabled         bool `json:"enabled"`
	RingBufferBytes int  `json:"ring_buffer_bytes"`
	MaxEventsPerSec int  `json:"max_events_per_sec"`
}

// PrivilegeSeparation controls only fixed local Linux helper endpoints. Socket
// paths are local configuration and are never accepted from telemetry/Central.
type PrivilegeSeparation struct {
	Enabled         bool   `json:"enabled"`
	SensorSocket    string `json:"sensor_socket"`
	ResponseSocket  string `json:"response_socket"`
	MaxMessageBytes int    `json:"max_message_bytes"`
	RequestTimeout  string `json:"request_timeout"`
}

// Detection controls the local deterministic detector. These settings only
// affect alerting; they never authorize a containment or other state change.
type Detection struct {
	AuthFailureThreshold int    `json:"auth_failure_threshold"`
	AuthFailureWindow    string `json:"auth_failure_window"`
}

// Protection configures the local Windows malware-prevention gate. Findings
// remain advisory in audit mode; enforce mode permits only the bounded actions
// implemented by the protection controller.
type Protection struct {
	Enabled             bool     `json:"enabled"`
	Mode                string   `json:"mode"`
	AuditPeriod         string   `json:"audit_period"`
	SuspiciousThreshold int      `json:"suspicious_threshold"`
	MaliciousThreshold  int      `json:"malicious_threshold"`
	AutoKill            bool     `json:"auto_kill"`
	AutoQuarantine      bool     `json:"auto_quarantine"`
	ProtectedPaths      []string `json:"protected_paths"`
	Exclusions          []string `json:"exclusions"`
}

type MalwareScanner struct {
	Enabled               bool     `json:"enabled"`
	YaraExecutable        string   `json:"yara_executable"`
	YaraRules             string   `json:"yara_rules"`
	YaraManifest          string   `json:"yara_manifest"`
	QuickPaths            []string `json:"quick_paths"`
	QuickInterval         string   `json:"quick_interval"`
	FullInterval          string   `json:"full_interval"`
	ScanTimeout           string   `json:"scan_timeout"`
	Workers               int      `json:"workers"`
	MaxAutomaticFileBytes int64    `json:"max_automatic_file_bytes"`
	MaxScheduledFileBytes int64    `json:"max_scheduled_file_bytes"`
	MaxFilesPerScan       int      `json:"max_files_per_scan"`
	HashDenylist          []string `json:"hash_denylist,omitempty"`
	HashAllowlist         []string `json:"hash_allowlist,omitempty"`
}

type Reputation struct {
	Enabled   bool   `json:"enabled"`
	Endpoint  string `json:"endpoint"`
	APIKeyEnv string `json:"api_key_env"`
	Timeout   string `json:"timeout"`
	CacheTTL  string `json:"cache_ttl"`
}

type Retention struct {
	EvidenceDays        int   `json:"evidence_days"`
	EvidenceMaxBytes    int64 `json:"evidence_max_bytes"`
	QuarantineDays      int   `json:"quarantine_days"`
	QuarantineMaxBytes  int64 `json:"quarantine_max_bytes"`
	JournalSegmentBytes int64 `json:"journal_segment_bytes"`
}

type Transport struct {
	Enabled            bool   `json:"enabled"`
	Endpoint           string `json:"endpoint"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	CAFile             string `json:"ca_file"`
	ServerName         string `json:"server_name,omitempty"`
	Timeout            string `json:"timeout"`
	FlushInterval      string `json:"flush_interval"`
	BatchSize          int    `json:"batch_size"`
	PendingWarn        int    `json:"pending_warn"`
	AutoRenew          bool   `json:"auto_renew"`
	RenewalEndpoint    string `json:"renewal_endpoint"`
	RenewBefore        string `json:"renew_before"`
	RenewCheckInterval string `json:"renew_check_interval"`
}

type Config struct {
	AgentID             string              `json:"agent_id"`
	TenantID            string              `json:"tenant_id"`
	DataDir             string              `json:"data_dir"`
	PollInterval        time.Duration       `json:"-"`
	Poll                string              `json:"poll_interval"`
	Sources             []Source            `json:"sources"`
	NativeSources       []NativeSource      `json:"native_sources"`
	API                 API                 `json:"api"`
	Tools               ToolPolicy          `json:"tools"`
	AI                  AI                  `json:"ai"`
	Detection           Detection           `json:"detection"`
	Protection          Protection          `json:"protection"`
	Scanner             MalwareScanner      `json:"scanner"`
	Reputation          Reputation          `json:"reputation"`
	Retention           Retention           `json:"retention"`
	Inventory           Inventory           `json:"inventory"`
	ProcessGraph        ProcessGraph        `json:"process_graph"`
	ProcessNetwork      ProcessNetwork      `json:"process_network"`
	EBPFSensor          EBPFSensor          `json:"ebpf_sensor"`
	PrivilegeSeparation PrivilegeSeparation `json:"privilege_separation"`
	Transport           Transport           `json:"transport"`
	Central             Central             `json:"central"`
}

func Default() Config {
	return Config{
		DataDir:      defaultDataDir(),
		PollInterval: 2 * time.Second,
		Poll:         "2s",
		API: API{
			Enabled:   true,
			Listen:    "127.0.0.1:9477",
			TokenFile: "agent-api.token",
		},
		Tools: ToolPolicy{
			PolicyFile:   "policies/default-policy.json",
			AllowedPaths: []string{"."},
		},
		AI: AI{
			Enabled: false, Timeout: "30s", MinimumSeverity: model.SeverityHigh,
			QueueSize: 64, MinInterval: "10s", AuditLogFile: "llm.audit.jsonl",
		},
		Detection: Detection{
			AuthFailureThreshold: 6,
			AuthFailureWindow:    "5m",
		},
		Protection: Protection{
			Enabled: runtime.GOOS == "windows", Mode: "audit", AuditPeriod: "168h",
			SuspiciousThreshold: 70, MaliciousThreshold: 95,
			AutoKill: true, AutoQuarantine: true,
		},
		Scanner: MalwareScanner{
			Enabled: runtime.GOOS == "windows", QuickInterval: "24h", FullInterval: "168h", ScanTimeout: "30s",
			Workers: 2, MaxAutomaticFileBytes: 128 * 1024 * 1024,
			MaxScheduledFileBytes: 512 * 1024 * 1024, MaxFilesPerScan: 50000,
		},
		Reputation: Reputation{Enabled: false, Timeout: "5s", CacheTTL: "24h"},
		Retention: Retention{
			EvidenceDays: 30, EvidenceMaxBytes: 5 * 1024 * 1024 * 1024,
			QuarantineDays: 90, QuarantineMaxBytes: 10 * 1024 * 1024 * 1024,
			JournalSegmentBytes: 256 * 1024 * 1024,
		},
		Inventory: Inventory{
			Enabled:          true,
			Interval:         "15m",
			CommandTimeout:   "10s",
			IncludeProcesses: true,
			IncludeServices:  true,
			IncludeListeners: true,
			IncludeSoftware:  true,
			MaxItems:         512,
		},
		ProcessGraph: ProcessGraph{
			Enabled:                true,
			ReconcileInterval:      "30s",
			MaxProcesses:           4096,
			MaxExitedProcesses:     2048,
			MaxCommandLineBytes:    4096,
			MaxExecutableHashBytes: 128 * 1024 * 1024,
		},
		ProcessNetwork: ProcessNetwork{
			Enabled:            true,
			ReconcileInterval:  "30s",
			MaxProcesses:       4096,
			MaxSockets:         8192,
			MaxFileDescriptors: 65536,
		},
		EBPFSensor: EBPFSensor{
			Enabled:         true,
			RingBufferBytes: 16 * 1024 * 1024,
			MaxEventsPerSec: 20000,
		},
		PrivilegeSeparation: PrivilegeSeparation{
			SensorSocket: "/run/ntagentshield-sensor/sensor.sock", ResponseSocket: "/run/ntagentshield-response/response.sock",
			MaxMessageBytes: 256 * 1024, RequestTimeout: "5s",
		},
		Transport: Transport{
			Enabled:            false,
			Endpoint:           "",
			CertFile:           "certs/client.crt",
			KeyFile:            "agent-identity.key",
			CAFile:             "certs/ca.crt",
			Timeout:            "15s",
			FlushInterval:      "2s",
			BatchSize:          100,
			PendingWarn:        10000,
			AutoRenew:          true,
			RenewBefore:        "168h",
			RenewCheckInterval: "1h",
		},
		Central: Central{
			HeartbeatInterval: "60s",
			BatchInterval:     "10s",
			MaxBatch:          100,
			QueueSize:         2000,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	content, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.Poll == "" {
		cfg.Poll = "2s"
	}
	cfg.PollInterval, err = time.ParseDuration(cfg.Poll)
	if err != nil {
		return Config{}, fmt.Errorf("invalid poll_interval: %w", err)
	}
	cfg.applyDefaults(path)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults(configPath string) {
	base := filepath.Dir(configPath)
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Clean(filepath.Join(base, c.DataDir))
	}
	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:9477"
	}
	if c.API.TokenFile == "" {
		c.API.TokenFile = "agent-api.token"
	}
	if !filepath.IsAbs(c.API.TokenFile) {
		c.API.TokenFile = filepath.Join(c.DataDir, c.API.TokenFile)
	}
	if c.AI.Timeout == "" {
		c.AI.Timeout = "30s"
	}
	if c.AI.MinimumSeverity == "" {
		c.AI.MinimumSeverity = model.SeverityHigh
	}
	if c.AI.QueueSize <= 0 {
		c.AI.QueueSize = 64
	}
	if c.AI.MinInterval == "" {
		c.AI.MinInterval = "10s"
	}
	if c.AI.AuditLogFile == "" {
		c.AI.AuditLogFile = "llm.audit.jsonl"
	}
	if c.AI.APIKeyFile != "" && !filepath.IsAbs(c.AI.APIKeyFile) {
		c.AI.APIKeyFile = filepath.Join(c.DataDir, c.AI.APIKeyFile)
	}
	if !filepath.IsAbs(c.AI.AuditLogFile) {
		c.AI.AuditLogFile = filepath.Join(c.DataDir, c.AI.AuditLogFile)
	}
	if c.Tools.PolicyFile == "" {
		c.Tools.PolicyFile = "policies/default-policy.json"
	}
	if !filepath.IsAbs(c.Tools.PolicyFile) {
		c.Tools.PolicyFile = filepath.Clean(filepath.Join(base, c.Tools.PolicyFile))
	}
	if c.Inventory.Interval == "" {
		c.Inventory.Interval = "15m"
	}
	if c.Detection.AuthFailureThreshold == 0 {
		c.Detection.AuthFailureThreshold = 6
	}
	if c.Detection.AuthFailureWindow == "" {
		c.Detection.AuthFailureWindow = "5m"
	}
	if c.Protection.Mode == "" {
		c.Protection.Mode = "audit"
	}
	c.Protection.Mode = strings.ToLower(strings.TrimSpace(c.Protection.Mode))
	if c.Protection.AuditPeriod == "" {
		c.Protection.AuditPeriod = "168h"
	}
	if c.Protection.SuspiciousThreshold == 0 {
		c.Protection.SuspiciousThreshold = 70
	}
	if c.Protection.MaliciousThreshold == 0 {
		c.ProtecßÞô¶‰žËkºwµçUÉÙ…°°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹AÉ½•ÍÍ9•ÑÝ½É¬¹I•½¹¥±•%¹Ñ•ÉÙ…°¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹É•½¹¥±•}¥¹Ñ•ÉÙ…°è€•Üˆ°•ÉÈ¤($%ô($%¥˜¥¹Ñ•ÉÙ…°€ðÑ¥µ”¹M•½¹ñð¥¹Ñ•ÉÙ…°€øÑ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹É•½¹¥±•}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€Å ˆ¤($%ô($%¥˜Œ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…áAÉ½•ÍÍ•Ì€ð€ÄñðŒ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…áAÉ½•ÍÍ•Ì€ø€ÄØÌàÐì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹µ…á}ÁÉ½•ÍÍ•ÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÄØÌàÐˆ¤($%ô($%¥˜Œ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…áM½­•ÑÌ€ð€ÄñðŒ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…áM½­•ÑÌ€ø€ÌÈÜØàì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹µ…á}Í½­•ÑÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÌÈÜØàˆ¤($%ô($%¥˜Œ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…á¥±••ÍÉ¥ÁÑ½ÉÌ€ð€ÄñðŒ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…á¥±••ÍÉ¥ÁÑ½ÉÌ€ø€ÈØÈÄÐÐì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹µ…á}™¥±•}‘•ÍÉ¥ÁÑ½ÉÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÈØÈÄÐÐˆ¤($%ô($%¥˜Œ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…áM½­•ÑÌ€øŒ¹AÉ½•ÍÍ9•ÑÝ½É¬¹5…á¥±••ÍÉ¥ÁÑ½ÉÌì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½•ÍÍ}¹•ÑÝ½É¬¹µ…á}Í½­•ÑÌ…¹¹½Ð•á••µ…á}™¥±•}‘•ÍÉ¥ÁÑ½ÉÌˆ¤($%ô(%ô(%¥˜Œ¹	AM•¹Í½È¹¹…‰±•ì($%¥˜Œ¹	AM•¹Í½È¹I¥¹	Õ™™•É	åÑ•Ì€ð€ÄððÈÀñðŒ¹	AM•¹Í½È¹I¥¹	Õ™™•É	åÑ•Ì€ø€ØÐ¨ÄÀÈÐ¨ÄÀÈÐñðŒ¹	AM•¹Í½È¹I¥¹	Õ™™•É	åÑ•Ì˜¡Œ¹	AM•¹Í½È¹I¥¹	Õ™™•É	åÑ•Ì´Ä¤€„ô€Àì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•‰Á™}Í•¹Í½È¹É¥¹}‰Õ™™•É}‰åÑ•ÌµÕÍÐ‰”„Á½Ý•È½˜ÑÝ¼‰•ÑÝ••¸€ÄÀÐàÔÜØ…¹€ØÜÄÀààØÐˆ¤($%ô($%¥˜Œ¹	AM•¹Í½È¹5…áÙ•¹ÑÍA•ÉM•Œ€ð€ÄÀÀñðŒ¹	AM•¹Í½È¹5…áÙ•¹ÑÍA•ÉM•Œ€ø€ÄÀÀÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•‰Á™}Í•¹Í½È¹µ…á}•Ù•¹ÑÍ}Á•É}Í•ŒµÕÍÐ‰”‰•ÑÝ••¸€ÄÀÀ…¹€ÄÀÀÀÀÀˆ¤($%ô(%ô(%¥˜Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹¹…‰±•ì($%¥˜€…™¥±•Á…Ñ ¹%Í‰Ì¡Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹M•¹Í½ÉM½­•Ð¤ñð€…™¥±•Á…Ñ ¹%Í‰Ì¡Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹I•ÍÁ½¹Í•M½­•Ð¤ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ¥Ù¥±••}Í•Á…É…Ñ¥½¸Í½­•ÐÁ…Ñ¡ÌµÕÍÐ‰”…‰Í½±ÕÑ”ˆ¤($%ô($%¥˜Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹M•¹Í½ÉM½­•Ð€ôôŒ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹I•ÍÁ½¹Í•M½­•Ðì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í•¹Í½È…¹É•ÍÁ½¹Í”¡•±Á•ÈÍ½­•ÑÌµÕÍÐ‰”‘¥ÍÑ¥¹Ðˆ¤($%ô($%¥˜Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹5…á5•ÍÍ…•	åÑ•Ì€ð€ÐÀäØñðŒ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹5…á5•ÍÍ…•	åÑ•Ì€ø€ÄÀÈÐ¨ÄÀÈÐì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ¥Ù¥±••}Í•Á…É…Ñ¥½¸¹µ…á}µ•ÍÍ…•}‰åÑ•ÌµÕÍÐ‰”‰•ÑÝ••¸€ÐÀäØ…¹€ÄÀÐàÔÜØˆ¤($%ô($%Ñ¥µ•½ÕÐ°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹AÉ¥Ù¥±••M•Á…É…Ñ¥½¸¹I•ÅÕ•ÍÑQ¥µ•½ÕÐ¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÁÉ¥Ù¥±••}Í•Á…É…Ñ¥½¸¹É•ÅÕ•ÍÑ}Ñ¥µ•½ÕÐè€•Üˆ°•ÉÈ¤($%ô($%¥˜Ñ¥µ•½ÕÐ€ð€ÄÀÀ©Ñ¥µ”¹5¥±±¥Í•½¹ñðÑ¥µ•½ÕÐ€øÑ¥µ”¹5¥¹ÕÑ”ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ¥Ù¥±••}Í•Á…É…Ñ¥½¸¹É•ÅÕ•ÍÑ}Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÄÀÁµÌ…¹€Å´ˆ¤($%ô(%ô(%¥˜Œ¹•Ñ•Ñ¥½¸¹ÕÑ¡…¥±ÕÉ•Q¡É•Í¡½±€ð€ÈñðŒ¹•Ñ•Ñ¥½¸¹ÕÑ¡…¥±ÕÉ•Q¡É•Í¡½±€ø€ÄÀÀì($%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰‘•Ñ•Ñ¥½¸¹…ÕÑ¡}™…¥±ÕÉ•}Ñ¡É•Í¡½±µÕÍÐ‰”‰•ÑÝ••¸€È…¹€ÄÀÀˆ¤(%ô(%…ÕÑ¡]¥¹‘½Ü°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹•Ñ•Ñ¥½¸¹ÕÑ¡…¥±ÕÉ•]¥¹‘½Ü¤(%¥˜•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥‘•Ñ•Ñ¥½¸¹…ÕÑ¡}™…¥±ÕÉ•}Ý¥¹‘½Üè€•Üˆ°•ÉÈ¤(%ô(%¥˜…ÕÑ¡]¥¹‘½Ü€ð€ÌÀ©Ñ¥µ”¹M•½¹ñð…ÕÑ¡]¥¹‘½Ü€ø€ÈÐ©Ñ¥µ”¹!½ÕÈì($%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰‘•Ñ•Ñ¥½¸¹…ÕÑ¡}™…¥±ÕÉ•}Ý¥¹‘½ÜµÕÍÐ‰”‰•ÑÝ••¸€ÌÁÌ…¹€ÈÑ ˆ¤(%ô(%¥˜Œ¹AÉ½Ñ•Ñ¥½¸¹¹…‰±•ì($%¥˜Œ¹AÉ½Ñ•Ñ¥½¸¹5½‘”€„ô€‰…Õ‘¥Ðˆ€˜˜Œ¹AÉ½Ñ•Ñ¥½¸¹5½‘”€„ô€‰•¹™½É”ˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½Ñ•Ñ¥½¸¹µ½‘”µÕÍÐ‰”…Õ‘¥Ð½È•¹™½É”ˆ¤($%ô($%…Õ‘¥ÑA•É¥½°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹AÉ½Ñ•Ñ¥½¸¹Õ‘¥ÑA•É¥½¤($%¥˜•ÉÈ€„ô¹¥°ñð…Õ‘¥ÑA•É¥½€ð€ÈÐ©Ñ¥µ”¹!½ÕÈñð…Õ‘¥ÑA•É¥½€ø€äÀ¨ÈÐ©Ñ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½Ñ•Ñ¥½¸¹…Õ‘¥Ñ}Á•É¥½µÕÍÐ‰”‰•ÑÝ••¸€ÈÑ …¹€ÈÄØÁ ˆ¤($%ô($%¥˜Œ¹AÉ½Ñ•Ñ¥½¸¹MÕÍÁ¥¥½ÕÍQ¡É•Í¡½±€ð€ÄñðŒ¹AÉ½Ñ•Ñ¥½¸¹MÕÍÁ¥¥½ÕÍQ¡É•Í¡½±€ø€ääñðŒ¹AÉ½Ñ•Ñ¥½¸¹5…±¥¥½ÕÍQ¡É•Í¡½±€ð€ÈñðŒ¹AÉ½Ñ•Ñ¥½¸¹5…±¥¥½ÕÍQ¡É•Í¡½±€ø€ÄÀÀñðŒ¹AÉ½Ñ•Ñ¥½¸¹MÕÍÁ¥¥½ÕÍQ¡É•Í¡½±€øôŒ¹AÉ½Ñ•Ñ¥½¸¹5…±¥¥½ÕÍQ¡É•Í¡½±ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½Ñ•Ñ¥½¸Ñ¡É•Í¡½±‘ÌµÕÍÐ‰”½É‘•É•Ù…±Õ•Ì‰•ÑÝ••¸€Ä…¹€ÄÀÀˆ¤($%ô($%¥˜±•¸¡Œ¹AÉ½Ñ•Ñ¥½¸¹AÉ½Ñ•Ñ•‘A…Ñ¡Ì¤€ôô€Àì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÁÉ½Ñ•Ñ¥½¸¹ÁÉ½Ñ•Ñ•‘}Á…Ñ¡ÌµÕÍÐ¹½Ð‰”•µÁÑäÝ¡•¸ÁÉ½Ñ•Ñ¥½¸¥Ì•¹…‰±•ˆ¤($%ô(%ô(%¥˜Œ¹M…¹¹•È¹¹…‰±•ì($%ÅÕ¥­%¹Ñ•ÉÙ…°°ÅÕ¥­ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹M…¹¹•È¹EÕ¥­%¹Ñ•ÉÙ…°¤($%™Õ±±%¹Ñ•ÉÙ…°°™Õ±±ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹M…¹¹•È¹Õ±±%¹Ñ•ÉÙ…°¤($%Ñ¥µ•½ÕÐ°Ñ¥µ•½ÕÑÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹M…¹¹•È¹M…¹Q¥µ•½ÕÐ¤($%¥˜ÅÕ¥­ÉÈ€„ô¹¥°ñðÅÕ¥­%¹Ñ•ÉÙ…°€ðÑ¥µ”¹!½ÕÈñðÅÕ¥­%¹Ñ•ÉÙ…°€ø€ÌÀ¨ÈÐ©Ñ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È¹ÅÕ¥­}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€Å …¹€ÜÈÁ ˆ¤($%ô($%¥˜™Õ±±ÉÈ€„ô¹¥°ñð™Õ±±%¹Ñ•ÉÙ…°€ð€ÈÐ©Ñ¥µ”¹!½ÕÈñð™Õ±±%¹Ñ•ÉÙ…°€ø€äÀ¨ÈÐ©Ñ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È¹™Õ±±}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€ÈÑ …¹€ÈÄØÁ ˆ¤($%ô($%¥˜Ñ¥µ•½ÕÑÉÈ€„ô¹¥°ñðÑ¥µ•½ÕÐ€ðÑ¥µ”¹M•½¹ñðÑ¥µ•½ÕÐ€ø€ÄÀ©Ñ¥µ”¹5¥¹ÕÑ”ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È¹Í…¹}Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€ÄÁ´ˆ¤($%ô($%¥˜Œ¹M…¹¹•È¹]½É­•ÉÌ€ð€ÄñðŒ¹M…¹¹•È¹]½É­•ÉÌ€ø€àì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È¹Ý½É­•ÉÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€àˆ¤($%ô($%¥˜Œ¹M…¹¹•È¹5…áÕÑ½µ…Ñ¥¥±•	åÑ•Ì€ð€ÄÀÈÐñðŒ¹M…¹¹•È¹5…áÕÑ½µ…Ñ¥¥±•	åÑ•Ì€ø€ÄÀÈÐ¨ÄÀÈÐ¨ÄÀÈÐñðŒ¹M…¹¹•È¹5…áM¡•‘Õ±•‘¥±•	åÑ•Ì€ðŒ¹M…¹¹•È¹5…áÕÑ½µ…Ñ¥¥±•	åÑ•ÌñðŒ¹M…¹¹•È¹5…áM¡•‘Õ±•‘¥±•	åÑ•Ì€ø€Ð¨ÄÀÈÐ¨ÄÀÈÐ¨ÄÀÈÐì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È™¥±”µÍ¥é”±¥µ¥ÑÌ…É”¥¹Ù…±¥ˆ¤($%ô($%¥˜Œ¹M…¹¹•È¹5…á¥±•ÍA•ÉM…¸€ð€ÄñðŒ¹M…¹¹•È¹5…á¥±•ÍA•ÉM…¸€ø€ÄÀÀÀÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Í…¹¹•È¹µ…á}™¥±•Í}Á•É}Í…¸µÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÄÀÀÀÀÀÀˆ¤($%ô(%ô(%¥˜Œ¹I•ÁÕÑ…Ñ¥½¸¹¹…‰±•ì($%¥˜•ÉÈ€èôÙ…±¥‘…Ñ•!QQAMUI0¡Œ¹I•ÁÕÑ…Ñ¥½¸¹¹‘Á½¥¹Ð°€‰É•ÁÕÑ…Ñ¥½¸¹•¹‘Á½¥¹Ðˆ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸•ÉÈ($%ô($%¥˜Ñ¥µ•½ÕÐ°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹I•ÁÕÑ…Ñ¥½¸¹Q¥µ•½ÕÐ¤ì•ÉÈ€„ô¹¥°ñðÑ¥µ•½ÕÐ€ðÑ¥µ”¹M•½¹ñðÑ¥µ•½ÕÐ€ø€ÌÀ©Ñ¥µ”¹M•½¹ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰É•ÁÕÑ…Ñ¥½¸¹Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€ÌÁÌˆ¤($%ô($%¥˜ÑÑ°°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹I•ÁÕÑ…Ñ¥½¸¹…¡•QQ0¤ì•ÉÈ€„ô¹¥°ñðÑÑ°€ðÑ¥µ”¹5¥¹ÕÑ”ñðÑÑ°€ø€Ü¨ÈÐ©Ñ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰É•ÁÕÑ…Ñ¥½¸¹…¡•}ÑÑ°µÕÍÐ‰”‰•ÑÝ••¸€Å´…¹€ÄØá ˆ¤($%ô(%ô(%¥˜Œ¹I•Ñ•¹Ñ¥½¸¹Ù¥‘•¹•…åÌ€ð€ÄñðŒ¹I•Ñ•¹Ñ¥½¸¹Ù¥‘•¹•…åÌ€ø€ÌØÔÀñðŒ¹I•Ñ•¹Ñ¥½¸¹EÕ…É…¹Ñ¥¹•…åÌ€ð€ÄñðŒ¹I•Ñ•¹Ñ¥½¸¹EÕ…É…¹Ñ¥¹•…åÌ€ø€ÌØÔÀì($%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰É•Ñ•¹Ñ¥½¸‘…ä±¥µ¥ÑÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÌØÔÀˆ¤(%ô(%¥˜Œ¹I•Ñ•¹Ñ¥½¸¹)½ÕÉ¹…±M•µ•¹Ñ	åÑ•Ì€ð€ÄØ¨ÄÀÈÐ¨ÄÀÈÐñðŒ¹I•Ñ•¹Ñ¥½¸¹)½ÕÉ¹…±M•µ•¹Ñ	åÑ•Ì€ø€Ð¨ÄÀÈÐ¨ÄÀÈÐ¨ÄÀÈÐñðŒ¹I•Ñ•¹Ñ¥½¸¹Ù¥‘•¹•5…á	åÑ•Ì€ðŒ¹I•Ñ•¹Ñ¥½¸¹)½ÕÉ¹…±M•µ•¹Ñ	åÑ•ÌñðŒ¹I•Ñ•¹Ñ¥½¸¹EÕ…É…¹Ñ¥¹•5…á	åÑ•Ì€ð€ÄÀÈÐ¨ÄÀÈÐì($%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰É•Ñ•¹Ñ¥½¸‰åÑ”±¥µ¥ÑÌ…É”¥¹Ù…±¥ˆ¤(%ô(%¥˜Œ¹QÉ…¹ÍÁ½ÉÐ¹¹…‰±•ì($%¥˜ÍÑÉ¥¹Ì¹QÉ¥µMÁ…”¡Œ¹Q•¹…¹Ñ%¤€ôô€ˆˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Ñ•¹…¹Ñ}¥¥ÌÉ•ÅÕ¥É•Ý¡•¸ÑÉ…¹ÍÁ½ÉÐ¥Ì•¹…‰±•ˆ¤($%ô($%¥˜•ÉÈ€èôÙ…±¥‘…Ñ•!QQAMUI0¡Œ¹QÉ…¹ÍÁ½ÉÐ¹¹‘Á½¥¹Ð°€‰ÑÉ…¹ÍÁ½ÉÐ¹•¹‘Á½¥¹Ðˆ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸•ÉÈ($%ô($%¥˜Œ¹QÉ…¹ÍÁ½ÉÐ¹•ÉÑ¥±”€ôô€ˆˆñðŒ¹QÉ…¹ÍÁ½ÉÐ¹-•å¥±”€ôô€ˆˆñðŒ¹QÉ…¹ÍÁ½ÉÐ¹¥±”€ôô€ˆˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ•ÉÑ}™¥±”°­•å}™¥±”°…¹…}™¥±”…É”É•ÅÕ¥É•ˆ¤($%ô($%Ñ¥µ•½ÕÐ°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹QÉ…¹ÍÁ½ÉÐ¹Q¥µ•½ÕÐ¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÑÉ…¹ÍÁ½ÉÐ¹Ñ¥µ•½ÕÐè€•Üˆ°•ÉÈ¤($%ô($%¥˜Ñ¥µ•½ÕÐ€ðÑ¥µ”¹M•½¹ñðÑ¥µ•½ÕÐ€ø€È©Ñ¥µ”¹5¥¹ÕÑ”ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€É´ˆ¤($%ô($%™±ÕÍ¡%¹Ñ•ÉÙ…°°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹QÉ…¹ÍÁ½ÉÐ¹±ÕÍ¡%¹Ñ•ÉÙ…°¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÑÉ…¹ÍÁ½ÉÐ¹™±ÕÍ¡}¥¹Ñ•ÉÙ…°è€•Üˆ°•ÉÈ¤($%ô($%¥˜™±ÕÍ¡%¹Ñ•ÉÙ…°€ð€ÈÔÀ©Ñ¥µ”¹5¥±±¥Í•½¹ñð™±ÕÍ¡%¹Ñ•ÉÙ…°€øÑ¥µ”¹5¥¹ÕÑ”ì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹™±ÕÍ¡}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€ÈÔÁµÌ…¹€Å´ˆ¤($%ô($%¥˜Œ¹QÉ…¹ÍÁ½ÉÐ¹	…Ñ¡M¥é”€ð€ÄñðŒ¹QÉ…¹ÍÁ½ÉÐ¹	…Ñ¡M¥é”€ø€ÄÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹‰…Ñ¡}Í¥é”µÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÄÀÀÀˆ¤($%ô($%¥˜Œ¹QÉ…¹ÍÁ½ÉÐ¹A•¹‘¥¹]…É¸€ð€ÄÀÀñðŒ¹QÉ…¹ÍÁ½ÉÐ¹A•¹‘¥¹]…É¸€ø€ÄÀÀÀÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹Á•¹‘¥¹}Ý…É¸µÕÍÐ‰”‰•ÑÝ••¸€ÄÀÀ…¹€ÄÀÀÀÀÀÀˆ¤($%ô($%¥˜Œ¹QÉ…¹ÍÁ½ÉÐ¹ÕÑ½I•¹•Üì($$%¥˜•ÉÈ€èôÙ…±¥‘…Ñ•!QQAMUI0¡Œ¹QÉ…¹ÍÁ½ÉÐ¹I•¹•Ý…±¹‘Á½¥¹Ð°€‰ÑÉ…¹ÍÁ½ÉÐ¹É•¹•Ý…±}•¹‘Á½¥¹Ðˆ¤ì•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸•ÉÈ($$%ô($$%É•¹•Ý	•™½É”°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹QÉ…¹ÍÁ½ÉÐ¹I•¹•Ý	•™½É”¤($$%¥˜•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÑÉ…¹ÍÁ½ÉÐ¹É•¹•Ý}‰•™½É”è€•Üˆ°•ÉÈ¤($$%ô($$%¥˜É•¹•Ý	•™½É”€ðÑ¥µ”¹!½ÕÈñðÉ•¹•Ý	•™½É”€ø€äÀ¨ÈÐ©Ñ¥µ”¹!½ÕÈì($$$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹É•¹•Ý}‰•™½É”µÕÍÐ‰”‰•ÑÝ••¸€Å …¹€ÈÄØÁ ˆ¤($$%ô($$%¡•­%¹Ñ•ÉÙ…°°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹QÉ…¹ÍÁ½ÉÐ¹I•¹•Ý¡•­%¹Ñ•ÉÙ…°¤($$%¥˜•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥ÑÉ…¹ÍÁ½ÉÐ¹É•¹•Ý}¡•­}¥¹Ñ•ÉÙ…°è€•Üˆ°•ÉÈ¤($$%ô($$%¥˜¡•­%¹Ñ•ÉÙ…°€ðÑ¥µ”¹5¥¹ÕÑ”ñð¡•­%¹Ñ•ÉÙ…°€ø€ÈÐ©Ñ¥µ”¹!½ÕÈì($$$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰ÑÉ…¹ÍÁ½ÉÐ¹É•¹•Ý}¡•­}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€Å´…¹€ÈÑ ˆ¤($$%ô($%ô(%ô(%¥˜Œ¹•¹ÑÉ…°¹¹…‰±•ì($%Á…ÉÍ•°•ÉÈ€èôÕÉ°¹A…ÉÍ”¡ÍÑÉ¥¹Ì¹QÉ¥µMÁ…”¡Œ¹•¹ÑÉ…°¹UI0¤¤($%¥˜•ÉÈ€„ô¹¥°ñðÁ…ÉÍ•¹M¡•µ”€ôô€ˆˆñðÁ…ÉÍ•¹!½ÍÐ€ôô€ˆˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹ÕÉ°µÕÍÐ‰”…¸…‰Í½±ÕÑ”!QQ@¡L¤UI0Ý¡•¸•¹ÑÉ…°¥Ì•¹…‰±•ˆ¤($%ô($%¥˜Á…ÉÍ•¹M¡•µ”€„ô€‰¡ÑÑÀˆ€˜˜Á…ÉÍ•¹M¡•µ”€„ô€‰¡ÑÑÁÌˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹ÕÉ°µÕÍÐÕÍ”¡ÑÑÀ½È¡ÑÑÁÌˆ¤($%ô($%¡•…ÉÑ‰•…Ð°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹•¹ÑÉ…°¹!•…ÉÑ‰•…Ñ%¹Ñ•ÉÙ…°¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥•¹ÑÉ…°¹¡•…ÉÑ‰•…Ñ}¥¹Ñ•ÉÙ…°è€•Üˆ°•ÉÈ¤($%ô($%¥˜¡•…ÉÑ‰•…Ð€ð€ÄÔ©Ñ¥µ”¹M•½¹ñð¡•…ÉÑ‰•…Ð€ø€ÈÐ©Ñ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹¡•…ÉÑ‰•…Ñ}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€ÄÕÌ…¹€ÈÑ ˆ¤($%ô($%‰…Ñ °•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Œ¹•¹ÑÉ…°¹	…Ñ¡%¹Ñ•ÉÙ…°¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥•¹ÑÉ…°¹‰…Ñ¡}¥¹Ñ•ÉÙ…°è€•Üˆ°•ÉÈ¤($%ô($%¥˜‰…Ñ €ðÑ¥µ”¹M•½¹ñð‰…Ñ €øÑ¥µ”¹!½ÕÈì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹‰…Ñ¡}¥¹Ñ•ÉÙ…°µÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€Å ˆ¤($%ô($%¥˜Œ¹•¹ÑÉ…°¹5…á	…Ñ €ð€ÄñðŒ¹•¹ÑÉ…°¹5…á	…Ñ €ø€ÔÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹µ…á}‰…Ñ µÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÔÀÀÀˆ¤($%ô($%¥˜Œ¹•¹ÑÉ…°¹EÕ•Õ•M¥é”€ðŒ¹•¹ÑÉ…°¹5…á	…Ñ ñðŒ¹•¹ÑÉ…°¹EÕ•Õ•M¥é”€ø€ÄÀÀÀÀÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹ÅÕ•Õ•}Í¥é”µÕÍÐ‰”…Ð±•…ÍÐµ…á}‰…Ñ …¹¹¼µ½É”Ñ¡…¸€ÄÀÀÀÀÀˆ¤($%ô($%¥˜ÍÑÉ¥¹Ì¹QÉ¥µMÁ…”¡Œ¹•¹ÑÉ…°¹A%-•å¥±”¤€ôô€ˆˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•¹ÑÉ…°¹…Á¥}­•å}™¥±”¥ÌÉ•ÅÕ¥É•Ý¡•¸•¹ÑÉ…°¥Ì•¹…‰±•ˆ¤($%ô(%ô(%Í••¸€èôµ…ÁmÍÑÉ¥¹uÍÑÉÕÑíõíô(%™½È|°Í½ÕÉ”€èôÉ…¹”Œ¹M½ÕÉ•Ìì($%¥˜€…Í½ÕÉ”¹¹…‰±•ì($$%½¹Ñ¥¹Õ”($%ô($%¥˜Í½ÕÉ”¹%€ôô€ˆˆñðÍ½ÕÉ”¹A…Ñ €ôô€ˆˆñðÍ½ÕÉ”¹½Éµ…Ð€ôô€ˆˆì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰•… •¹…‰±•Í½ÕÉ”É•ÅÕ¥É•Ì¥°Á…Ñ °…¹™½Éµ…Ðˆ¤($%ô($%¥˜|°½¬€èôÍ••¹mÍ½ÕÉ”¹%tì½¬ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰‘ÕÁ±¥…Ñ”Í½ÕÉ”¥€•Äˆ°Í½ÕÉ”¹%¤($%ô($%Í••¹mÍ½ÕÉ”¹%t€ôÍÑÉÕÑíõíô(%ô(%™½È|°Í½ÕÉ”€èôÉ…¹”Œ¹9…Ñ¥Ù•M½ÕÉ•Ìì($%¥˜€…Í½ÕÉ”¹¹…‰±•ì($$%½¹Ñ¥¹Õ”($%ô($%¥˜€…¹…Ñ¥Ù•M½ÕÉ•%A…ÑÑ•É¸¹5…Ñ¡MÑÉ¥¹œ¡Í½ÕÉ”¹%¤ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”¥€•ÄµÕÍÐµ…Ñ €•Ìˆ°Í½ÕÉ”¹%°¹…Ñ¥Ù•M½ÕÉ•%A…ÑÑ•É¸¹MÑÉ¥¹œ ¤¤($%ô($%¥˜|°½¬€èôÍ••¹mÍ½ÕÉ”¹%tì½¬ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰‘ÕÁ±¥…Ñ”Í½ÕÉ”¥€•Äˆ°Í½ÕÉ”¹%¤($%ô($%Í••¹mÍ½ÕÉ”¹%t€ôÍÑÉÕÑíõíô($%¥˜Í½ÕÉ”¹5…á	…Ñ €ð€ÄñðÍ½ÕÉ”¹5…á	…Ñ €ø€ÔÀÀÀì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ìµ…á}‰…Ñ µÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÔÀÀÀˆ°Í½ÕÉ”¹%¤($%ô($%Ñ¥µ•½ÕÐ°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Í½ÕÉ”¹½µµ…¹‘Q¥µ•½ÕÐ¤($%¥˜•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì½µµ…¹‘}Ñ¥µ•½ÕÐè€•Üˆ°Í½ÕÉ”¹%°•ÉÈ¤($%ô($%¥˜Ñ¥µ•½ÕÐ€ðÑ¥µ”¹M•½¹ñðÑ¥µ•½ÕÐ€ø€È©Ñ¥µ”¹5¥¹ÕÑ”ì($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì½µµ…¹‘}Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÅÌ…¹€É´ˆ°Í½ÕÉ”¹%¤($%ô($%ÍÝ¥Ñ Í½ÕÉ”¹-¥¹ì($%…Í”€‰Ý¥¹‘½ÝÍ}•Ù•¹Ñ±½œˆ°€‰Ý¥¹•Ù•¹Ñ±½œˆ°€‰ÍåÍµ½¸ˆè($$%¥˜€…Ý¥¹‘½ÝÍ¡…¹¹•±A…ÑÑ•É¸¹5…Ñ¡MÑÉ¥¹œ¡Í½ÕÉ”¹¡…¹¹•°¤ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì¡…Ì¥¹Ù…±¥]¥¹‘½ÝÌ•Ù•¹Ð¡…¹¹•°ˆ°Í½ÕÉ”¹%¤($$%ô($$%¥˜±•¸¡Í½ÕÉ”¹Ù•¹Ñ%Ì¤€ø€ÄÈàì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•ÌÍÕÁÁ½ÉÑÌ…Ðµ½ÍÐ€ÄÈà•Ù•¹Ð%Ìˆ°Í½ÕÉ”¹%¤($$%ô($$%™½È|°•Ù•¹Ñ%€èôÉ…¹”Í½ÕÉ”¹Ù•¹Ñ%Ìì($$$%¥˜•Ù•¹Ñ%€ð€Äñð•Ù•¹Ñ%€ø€ØÔÔÌÔì($$$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì¡…Ì¥¹Ù…±¥•Ù•¹Ð%€•ˆ°Í½ÕÉ”¹%°•Ù•¹Ñ%¤($$$%ô($$%ô($%…Í”€‰©½ÕÉ¹…±ˆ°€‰©½ÕÉ¹…±Ñ°ˆè($$%¥˜±•¸¡Í½ÕÉ”¹U¹¥ÑÌ¤€ø€ÌÈñð±•¸¡Í½ÕÉ”¹%‘•¹Ñ¥™¥•ÉÌ¤€ø€ÌÈì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•ÌÍÕÁÁ½ÉÑÌ…Ðµ½ÍÐ€ÌÈÕ¹¥ÑÌ…¹¥‘•¹Ñ¥™¥•ÉÌˆ°Í½ÕÉ”¹%¤($$%ô($$%™½È|°Ù…±Õ”€èôÉ…¹”…ÁÁ•¹¡…ÁÁ•¹¡muÍÑÉ¥¹íô°Í½ÕÉ”¹U¹¥ÑÌ¸¸¸¤°Í½ÕÉ”¹%‘•¹Ñ¥™¥•ÉÌ¸¸¸¤ì($$$%¥˜Ù…±Õ”€ôô€ˆˆñð±•¸¡Ù…±Õ”¤€ø€ÄÈàñðÍÑÉ¥¹Ì¹½¹Ñ…¥¹Í¹ä¡Ù…±Õ”°€‰qàÀÁqÉq¸ˆ¤ì($$$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì½¹Ñ…¥¹Ì…¸¥¹Ù…±¥©½ÕÉ¹…±™¥±Ñ•Èˆ°Í½ÕÉ”¹%¤($$$%ô($$%ô($%…Í”€‰…Õ‘¥Ñˆ°€‰±¥¹Õá}…Õ‘¥Ñˆè($$%¥˜Í½ÕÉ”¹A…Ñ €ôô€ˆˆñð€…™¥±•Á…Ñ ¹%Í‰Ì¡Í½ÕÉ”¹A…Ñ ¤ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì…Õ‘¥ÑÁ…Ñ µÕÍÐ‰”…‰Í½±ÕÑ”ˆ°Í½ÕÉ”¹%¤($$%ô($$%¥˜Í½ÕÉ”¹5…áÑ¥Ù•M•É¥…±Ì€ð€ÄñðÍ½ÕÉ”¹5…áÑ¥Ù•M•É¥…±Ì€ø€ÄÀÈÐì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ìµ…á}…Ñ¥Ù•}Í•É¥…±ÌµÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÄÀÈÐˆ°Í½ÕÉ”¹%¤($$%ô($$%¥˜Í½ÕÉ”¹5…áI•½É‘ÍA•ÉM•É¥…°€ð€ÄñðÍ½ÕÉ”¹5…áI•½É‘ÍA•ÉM•É¥…°€ø€ÄÀÈÐì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ìµ…á}É•½É‘Í}Á•É}Í•É¥…°µÕÍÐ‰”‰•ÑÝ••¸€Ä…¹€ÄÀÈÐˆ°Í½ÕÉ”¹%¤($$%ô($$%¥˜Í½ÕÉ”¹5…á	åÑ•ÍA•ÉM•É¥…°€ð€ÐÀäØñðÍ½ÕÉ”¹5…á	åÑ•ÍA•ÉM•É¥…°€ø€ÄÀÈÐ¨ÄÀÈÐì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ìµ…á}‰åÑ•Í}Á•É}Í•É¥…°µÕÍÐ‰”‰•ÑÝ••¸€ÐÀäØ…¹€ÄÀÐàÔÜØˆ°Í½ÕÉ”¹%¤($$%ô($$$¼¼Ñ¥Ù”É½ÕÁÌ…¹™¥¹…±¥é•É½ÕÁÌÝ…¥Ñ¥¹œ™½È‘ÕÉ…‰±”‰…Ñ ($$$¼¼…­¹½Ý±•‘•µ•¹Ð‰½Ñ É•Ñ…¥¸Á…ÉÍ•Õ¹ÑÉÕÍÑ••Ù¥‘•¹”¸	½Õ¹Ñ¡•¥È($$$¼¼½µ‰¥¹•Í•É¥…±¥é•¥¹ÁÕÐ‰Õ‘•ÐÉ…Ñ¡•ÈÑ¡…¸½¹±ä…Ñ¥Ù”Í•É¥…±Ì¸($$%¥˜¥¹ÐØÐ¡Í½ÕÉ”¹5…áÑ¥Ù•M•É¥…±Ì­Í½ÕÉ”¹5…á	…Ñ ¤©¥¹ÐØÐ¡Í½ÕÉ”¹5…á	åÑ•ÍA•ÉM•É¥…°¤€ø€ÌÈ¨ÄÀÈÐ¨ÄÀÈÐì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì…Õ‘¥Ð…ÍÍ•µ‰±•È…¹Á•¹‘¥¹œ‰…Ñ µ•µ½Éä‰Õ‘•Ð•á••‘Ì€ÌÈ5¥ˆ°Í½ÕÉ”¹%¤($$%ô($$%…ÍÍ•µ‰±åQ¥µ•½ÕÐ°•ÉÈ€èôÑ¥µ”¹A…ÉÍ•ÕÉ…Ñ¥½¸¡Í½ÕÉ”¹ÍÍ•µ‰±åQ¥µ•½ÕÐ¤($$%¥˜•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¥¹Ù…±¥¹…Ñ¥Ù”Í½ÕÉ”€•Ì…ÍÍ•µ‰±å}Ñ¥µ•½ÕÐè€•Üˆ°Í½ÕÉ”¹%°•ÉÈ¤($$%ô($$%¥˜…ÍÍ•µ‰±åQ¥µ•½ÕÐ€ð€ÄÀÀ©Ñ¥µ”¹5¥±±¥Í•½¹ñð…ÍÍ•µ‰±åQ¥µ•½ÕÐ€ø€Ô©Ñ¥µ”¹5¥¹ÕÑ”ì($$$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì…ÍÍ•µ‰±å}Ñ¥µ•½ÕÐµÕÍÐ‰”‰•ÑÝ••¸€ÄÀÁµÌ…¹€Õ´ˆ°Í½ÕÉ”¹%¤($$%ô($%‘•™…Õ±Ðè($$%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰¹…Ñ¥Ù”Í½ÕÉ”€•Ì¡…ÌÕ¹ÍÕÁÁ½ÉÑ•­¥¹€•Äˆ°Í½ÕÉ”¹%°Í½ÕÉ”¹-¥¹¤($%ô(%ô(%É•ÑÕÉ¸¹¥°)ô()™Õ¹ŒÙ…±¥‘…Ñ•!QQAMUI0¡Ù…±Õ”°¹…µ”ÍÑÉ¥¹œ¤•ÉÉ½Èì(%•¹‘Á½¥¹Ð°•ÉÈ€èôÕÉ°¹A…ÉÍ”¡ÍÑÉ¥¹Ì¹QÉ¥µMÁ…”¡Ù…±Õ”¤¤(%¥˜•ÉÈ€„ô¹¥°ñð•¹‘Á½¥¹Ð¹M¡•µ”€„ô€‰¡ÑÑÁÌˆñð•¹‘Á½¥¹Ð¹!½ÍÐ€ôô€ˆˆì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ˆ•ÌµÕÍÐ‰”…¸…‰Í½±ÕÑ”¡ÑÑÁÌUI0ˆ°¹…µ”¤(%ô(%É•ÑÕÉ¸¹¥°)ô()™Õ¹Œ¹ÍÕÉ••¹Ñ%¡™œ€©½¹™¥œ¤•ÉÉ½Èì(%¥˜™œ¹•¹Ñ%€„ô€ˆˆì($%É•ÑÕÉ¸¹¥°(%ô(%¥˜•ÉÈ€èô¹ÍÕÉ•…Ñ…¥È ©™œ¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸•ÉÈ(%ô(%¥‘•¹Ñ¥ÑåA…Ñ €èô™¥±•Á…Ñ ¹)½¥¸¡™œ¹…Ñ…¥È°€‰…•¹Ð¹¥ˆ¤(%¥˜½¹Ñ•¹Ð°•ÉÈ€èô½Ì¹I•…‘¥±”¡¥‘•¹Ñ¥ÑåA…Ñ ¤ì•ÉÈ€ôô¹¥°ì($%¥‘•¹Ñ¥Ñä€èôÍÑÉ¥¹Ì¹QÉ¥µMÁ…”¡ÍÑÉ¥¹œ¡½¹Ñ•¹Ð¤¤($%¥˜€…ÍÑÉ¥¹Ì¹!…ÍAÉ•™¥à¡¥‘•¹Ñ¥Ñä°€‰…•¹Ñ|ˆ¤ñð±•¸¡¥‘•¹Ñ¥Ñä¤€ð€ÈÀì($$%É•ÑÕÉ¸•ÉÉ½ÉÌ¹9•Ü ‰Á•ÉÍ¥ÍÑ•…•¹Ð¥‘•¹Ñ¥Ñä¥Ì¥¹Ù…±¥ˆ¤($%ô($%™œ¹•¹Ñ%€ô¥‘•¹Ñ¥Ñä($%É•ÑÕÉ¸½Ì¹¡µ½¡¥‘•¹Ñ¥ÑåA…Ñ °€Á¼ØÀÀ¤(%ô•±Í”¥˜€…•ÉÉ½ÉÌ¹%Ì¡•ÉÈ°½Ì¹ÉÉ9½Ñá¥ÍÐ¤ì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰É•…Á•ÉÍ¥ÍÑ•…•¹Ð¥‘•¹Ñ¥Ñäè€•Üˆ°•ÉÈ¤(%ô(%‰Õ˜€èôµ…­”¡mu‰åÑ”°€ÄØ¤(%¥˜|°•ÉÈ€èôÉ…¹¹I•…¡‰Õ˜¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰•¹•É…Ñ”…•¹Ð¥è€•Üˆ°•ÉÈ¤(%ô(%™œ¹•¹Ñ%€ô€‰…•¹Ñ|ˆ€¬¡•à¹¹½‘•Q½MÑÉ¥¹œ¡‰Õ˜¤(%¥˜•ÉÈ€èô½Ì¹]É¥Ñ•¥±”¡¥‘•¹Ñ¥ÑåA…Ñ °mu‰åÑ”¡™œ¹•¹Ñ%¬‰q¸ˆ¤°€Á¼ØÀÀ¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰Á•ÉÍ¥ÍÐ…•¹Ð¥‘•¹Ñ¥Ñäè€•Üˆ°•ÉÈ¤(%ô(%É•ÑÕÉ¸¹¥°)ô()™Õ¹Œ¹ÍÕÉ•…Ñ…¥È¡™œ½¹™¥œ¤•ÉÉ½Èì(%¥˜•ÉÈ€èô½Ì¹5­‘¥É±°¡™œ¹…Ñ…¥È°€Á¼ÜÀÀ¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸™µÐ¹ÉÉ½É˜ ‰É•…Ñ”‘…Ñ„‘¥Èè€•Üˆ°•ÉÈ¤(%ô(%É•ÑÕÉ¸½Ì¹¡µ½¡™œ¹…Ñ…¥È°€Á¼ÜÀÀ¤)ô()™Õ¹Œ‘•™…Õ±Ñ…Ñ…¥È ¤ÍÑÉ¥¹œì(%¥˜ÉÕ¹Ñ¥µ”¹==L€ôô€‰Ý¥¹‘½ÝÌˆì($%¥˜‰…Í”€èô½Ì¹•Ñ•¹Ø ‰AÉ½É…µ…Ñ„ˆ¤ì‰…Í”€„ô€ˆˆì($$%É•ÑÕÉ¸™¥±•Á…Ñ ¹)½¥¸¡‰…Í”°€‰9Q•¹ÑM¡¥•±ˆ¤($%ô(%ô(%É•ÑÕÉ¸€ˆ¸½‘…Ñ„ˆ)ô(