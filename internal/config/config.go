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
	Enabled     bool   `json:"enabled"`
	Endpoint    string `json:"endpoint"`
	Model       string `json:"model"`
	APIKeyEnv   string `json:"api_key_env"`
	AllowRemote bool   `json:"allow_remote"`
	Timeout     string `json:"timeout"`
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
		AI: AI{Enabled: false, Timeout: "30s"},
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
		c.Protection.MaliciousThreshold = 95
	}
	if len(c.Protection.ProtectedPaths) == 0 && runtime.GOOS == "windows" {
		c.Protection.ProtectedPaths = defaultWindowsProtectionPaths()
	}
	if c.Scanner.QuickInterval == "" {
		c.Scanner.QuickInterval = "24h"
	}
	if c.Scanner.FullInterval == "" {
		c.Scanner.FullInterval = "168h"
	}
	if c.Scanner.ScanTimeout == "" {
		c.Scanner.ScanTimeout = "30s"
	}
	if c.Scanner.Workers <= 0 {
		c.Scanner.Workers = 2
	}
	if c.Scanner.MaxAutomaticFileBytes <= 0 {
		c.Scanner.MaxAutomaticFileBytes = 128 * 1024 * 1024
	}
	if c.Scanner.MaxScheduledFileBytes <= 0 {
		c.Scanner.MaxScheduledFileBytes = 512 * 1024 * 1024
	}
	if c.Scanner.MaxFilesPerScan <= 0 {
		c.Scanner.MaxFilesPerScan = 50000
	}
	if len(c.Scanner.QuickPaths) == 0 {
		c.Scanner.QuickPaths = append([]string(nil), c.Protection.ProtectedPaths...)
	}
	if c.Reputation.Timeout == "" {
		c.Reputation.Timeout = "5s"
	}
	if c.Reputation.CacheTTL == "" {
		c.Reputation.CacheTTL = "24h"
	}
	if c.Retention.EvidenceDays <= 0 {
		c.Retention.EvidenceDays = 30
	}
	if c.Retention.EvidenceMaxBytes <= 0 {
		c.Retention.EvidenceMaxBytes = 5 * 1024 * 1024 * 1024
	}
	if c.Retention.QuarantineDays <= 0 {
		c.Retention.QuarantineDays = 90
	}
	if c.Retention.QuarantineMaxBytes <= 0 {
		c.Retention.QuarantineMaxBytes = 10 * 1024 * 1024 * 1024
	}
	if c.Retention.JournalSegmentBytes <= 0 {
		c.Retention.JournalSegmentBytes = 256 * 1024 * 1024
	}
	for _, paths := range []*[]string{&c.Protection.ProtectedPaths, &c.Protection.Exclusions, &c.Scanner.QuickPaths} {
		for i, path := range *paths {
			path = os.ExpandEnv(strings.TrimSpace(path))
			if path != "" && !filepath.IsAbs(path) {
				path = filepath.Clean(filepath.Join(base, path))
			}
			(*paths)[i] = filepath.Clean(path)
		}
	}
	for _, target := range []*string{&c.Scanner.YaraExecutable, &c.Scanner.YaraRules, &c.Scanner.YaraManifest} {
		if *target != "" && !filepath.IsAbs(*target) {
			*target = filepath.Clean(filepath.Join(base, *target))
		}
	}
	if c.Inventory.CommandTimeout == "" {
		c.Inventory.CommandTimeout = "10s"
	}
	if c.Inventory.MaxItems <= 0 {
		c.Inventory.MaxItems = 512
	}
	if c.ProcessGraph.ReconcileInterval == "" {
		c.ProcessGraph.ReconcileInterval = "30s"
	}
	if c.ProcessGraph.MaxProcesses <= 0 {
		c.ProcessGraph.MaxProcesses = 4096
	}
	if c.ProcessGraph.MaxExitedProcesses < 0 {
		c.ProcessGraph.MaxExitedProcesses = 0
	}
	if c.ProcessGraph.MaxExitedProcesses == 0 {
		c.ProcessGraph.MaxExitedProcesses = 2048
	}
	if c.ProcessGraph.MaxCommandLineBytes <= 0 {
		c.ProcessGraph.MaxCommandLineBytes = 4096
	}
	if c.ProcessGraph.MaxExecutableHashBytes <= 0 {
		c.ProcessGraph.MaxExecutableHashBytes = 128 * 1024 * 1024
	}
	if c.ProcessNetwork.ReconcileInterval == "" {
		c.ProcessNetwork.ReconcileInterval = "30s"
	}
	if c.ProcessNetwork.MaxProcesses <= 0 {
		c.ProcessNetwork.MaxProcesses = 4096
	}
	if c.ProcessNetwork.MaxSockets <= 0 {
		c.ProcessNetwork.MaxSockets = 8192
	}
	if c.ProcessNetwork.MaxFileDescriptors <= 0 {
		c.ProcessNetwork.MaxFileDescriptors = 65536
	}
	if c.EBPFSensor.RingBufferBytes <= 0 {
		c.EBPFSensor.RingBufferBytes = 16 * 1024 * 1024
	}
	if c.EBPFSensor.MaxEventsPerSec <= 0 {
		c.EBPFSensor.MaxEventsPerSec = 20000
	}
	if c.PrivilegeSeparation.SensorSocket == "" {
		c.PrivilegeSeparation.SensorSocket = "/run/ntagentshield-sensor/sensor.sock"
	}
	if c.PrivilegeSeparation.ResponseSocket == "" {
		c.PrivilegeSeparation.ResponseSocket = "/run/ntagentshield-response/response.sock"
	}
	if c.PrivilegeSeparation.MaxMessageBytes <= 0 {
		c.PrivilegeSeparation.MaxMessageBytes = 256 * 1024
	}
	if c.PrivilegeSeparation.RequestTimeout == "" {
		c.PrivilegeSeparation.RequestTimeout = "5s"
	}
	if c.Transport.CertFile == "" {
		c.Transport.CertFile = "certs/client.crt"
	}
	if c.Transport.KeyFile == "" {
		c.Transport.KeyFile = "agent-identity.key"
	}
	if c.Transport.CAFile == "" {
		c.Transport.CAFile = "certs/ca.crt"
	}
	for _, target := range []*string{&c.Transport.CertFile, &c.Transport.KeyFile, &c.Transport.CAFile} {
		if !filepath.IsAbs(*target) {
			*target = filepath.Clean(filepath.Join(c.DataDir, *target))
		}
	}
	if c.Transport.Timeout == "" {
		c.Transport.Timeout = "15s"
	}
	if c.Transport.FlushInterval == "" {
		c.Transport.FlushInterval = "2s"
	}
	if c.Transport.BatchSize <= 0 {
		c.Transport.BatchSize = 100
	}
	if c.Transport.PendingWarn <= 0 {
		c.Transport.PendingWarn = 10000
	}
	if c.Transport.RenewBefore == "" {
		c.Transport.RenewBefore = "168h"
	}
	if c.Transport.RenewCheckInterval == "" {
		c.Transport.RenewCheckInterval = "1h"
	}
	if c.Transport.RenewalEndpoint == "" && c.Transport.Endpoint != "" {
		if endpoint, err := url.Parse(c.Transport.Endpoint); err == nil && endpoint.Scheme != "" && endpoint.Host != "" {
			endpoint.Path = "/v1/agent/certificate/renew"
			endpoint.RawPath = ""
			endpoint.RawQuery = ""
			endpoint.Fragment = ""
			c.Transport.RenewalEndpoint = endpoint.String()
		}
	}
	if c.Central.HeartbeatInterval == "" {
		c.Central.HeartbeatInterval = "60s"
	}
	if c.Central.BatchInterval == "" {
		c.Central.BatchInterval = "10s"
	}
	if c.Central.MaxBatch <= 0 {
		c.Central.MaxBatch = 100
	}
	if c.Central.QueueSize <= 0 {
		c.Central.QueueSize = 2000
	}
	if c.Central.APIKeyFile == "" {
		c.Central.APIKeyFile = "central-api.key"
	}
	if c.Central.EnrollmentTokenFile == "" {
		c.Central.EnrollmentTokenFile = "central-enrollment.token"
	}
	if !filepath.IsAbs(c.Central.APIKeyFile) {
		c.Central.APIKeyFile = filepath.Join(c.DataDir, c.Central.APIKeyFile)
	}
	if !isRootedPath(c.Central.EnrollmentTokenFile) {
		c.Central.EnrollmentTokenFile = filepath.Clean(filepath.Join(base, c.Central.EnrollmentTokenFile))
	}
	for i := range c.Sources {
		if c.Sources[i].Trust == "" {
			c.Sources[i].Trust = model.TrustUntrustedTelemetry
		}
		if c.Sources[i].MaxBatch <= 0 {
			c.Sources[i].MaxBatch = 1000
		}
		if !filepath.IsAbs(c.Sources[i].Path) {
			c.Sources[i].Path = filepath.Clean(filepath.Join(base, c.Sources[i].Path))
		}
	}
	for i := range c.NativeSources {
		source := &c.NativeSources[i]
		source.Kind = strings.ToLower(strings.TrimSpace(source.Kind))
		if source.MaxBatch <= 0 {
			source.MaxBatch = 256
		}
		if source.CommandTimeout == "" {
			source.CommandTimeout = "15s"
		}
		if source.Kind == "auditd" || source.Kind == "linux_auditd" {
			if source.MaxActiveSerials <= 0 {
				source.MaxActiveSerials = 128
			}
			if source.MaxRecordsPerSerial <= 0 {
				source.MaxRecordsPerSerial = 64
			}
			if source.MaxBytesPerSerial <= 0 {
				source.MaxBytesPerSerial = 64 * 1024
			}
			if source.AssemblyTimeout == "" {
				source.AssemblyTimeout = "2s"
			}
		}
		if (source.Kind == "auditd" || source.Kind == "linux_auditd") && source.Path == "" {
			source.Path = "/var/log/audit/audit.log"
		}
		if source.Path != "" && !filepath.IsAbs(source.Path) {
			source.Path = filepath.Clean(filepath.Join(base, source.Path))
		}
		for unitIndex := range source.Units {
			source.Units[unitIndex] = strings.TrimSpace(source.Units[unitIndex])
		}
		for identifierIndex := range source.Identifiers {
			source.Identifiers[identifierIndex] = strings.TrimSpace(source.Identifiers[identifierIndex])
		}
	}
	for i, path := range c.Tools.AllowedPaths {
		if !filepath.IsAbs(path) {
			c.Tools.AllowedPaths[i] = filepath.Clean(filepath.Join(base, path))
		}
	}
}

// isRootedPath preserves slash-rooted paths from configurations shared across
// Unix and Windows. filepath.IsAbs alone treats /etc/... as relative on Windows.
func isRootedPath(value string) bool {
	return filepath.IsAbs(value) || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\")
}

func defaultWindowsProtectionPaths() []string {
	paths := []string{}
	if drive := os.Getenv("SystemDrive"); drive != "" {
		paths = append(paths, filepath.Join(drive+string(os.PathSeparator), "Users"))
	}
	if value := os.Getenv("ProgramData"); value != "" {
		paths = append(paths, value)
	}
	if value := os.Getenv("SystemRoot"); value != "" {
		paths = append(paths, filepath.Join(value, "Temp"))
	}
	return paths
}

func (c Config) Validate() error {
	if c.PollInterval < 100*time.Millisecond || c.PollInterval > 24*time.Hour {
		return errors.New("poll_interval must be between 100ms and 24h")
	}
	if c.API.Enabled {
		host, _, err := net.SplitHostPort(c.API.Listen)
		if err != nil {
			return fmt.Errorf("invalid api.listen: %w", err)
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			return errors.New("api.listen must be a loopback address; remote access uses the authenticated transport instead")
		}
	}
	if c.AI.Enabled {
		if strings.TrimSpace(c.AI.Endpoint) == "" || strings.TrimSpace(c.AI.Model) == "" {
			return errors.New("ai.endpoint and ai.model are required when AI is enabled")
		}
		if c.AI.Timeout == "" {
			c.AI.Timeout = "30s"
		}
		if _, err := time.ParseDuration(c.AI.Timeout); err != nil {
			return fmt.Errorf("invalid ai.timeout: %w", err)
		}
	}
	if c.Inventory.Enabled {
		interval, err := time.ParseDuration(c.Inventory.Interval)
		if err != nil {
			return fmt.Errorf("invalid inventory.interval: %w", err)
		}
		if interval < time.Minute || interval > 24*time.Hour {
			return errors.New("inventory.interval must be between 1m and 24h")
		}
		timeout, err := time.ParseDuration(c.Inventory.CommandTimeout)
		if err != nil {
			return fmt.Errorf("invalid inventory.command_timeout: %w", err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return errors.New("inventory.command_timeout must be between 1s and 2m")
		}
		if c.Inventory.MaxItems < 1 || c.Inventory.MaxItems > 10000 {
			return errors.New("inventory.max_items must be between 1 and 10000")
		}
	}
	if c.ProcessGraph.Enabled {
		interval, err := time.ParseDuration(c.ProcessGraph.ReconcileInterval)
		if err != nil {
			return fmt.Errorf("invalid process_graph.reconcile_interval: %w", err)
		}
		if interval < time.Second || interval > time.Hour {
			return errors.New("process_graph.reconcile_interval must be between 1s and 1h")
		}
		if c.ProcessGraph.MaxProcesses < 1 || c.ProcessGraph.MaxProcesses > 16384 {
			return errors.New("process_graph.max_processes must be between 1 and 16384")
		}
		if c.ProcessGraph.MaxExitedProcesses < 0 || c.ProcessGraph.MaxExitedProcesses > 16384 {
			return errors.New("process_graph.max_exited_processes must be between 0 and 16384")
		}
		if c.ProcessGraph.MaxCommandLineBytes < 256 || c.ProcessGraph.MaxCommandLineBytes > 64*1024 {
			return errors.New("process_graph.max_command_line_bytes must be between 256 and 65536")
		}
		if c.ProcessGraph.MaxExecutableHashBytes < 1024*1024 || c.ProcessGraph.MaxExecutableHashBytes > 1024*1024*1024 {
			return errors.New("process_graph.max_executable_hash_bytes must be between 1048576 and 1073741824")
		}
		if int64(c.ProcessGraph.MaxProcesses+c.ProcessGraph.MaxExitedProcesses)*int64(c.ProcessGraph.MaxCommandLineBytes) > 48*1024*1024 {
			return errors.New("process_graph retained command-line memory budget exceeds 48 MiB")
		}
	}
	if c.ProcessNetwork.Enabled {
		interval, err := time.ParseDuration(c.ProcessNetwork.ReconcileInterval)
		if err != nil {
			return fmt.Errorf("invalid process_network.reconcile_interval: %w", err)
		}
		if interval < time.Second || interval > time.Hour {
			return errors.New("process_network.reconcile_interval must be between 1s and 1h")
		}
		if c.ProcessNetwork.MaxProcesses < 1 || c.ProcessNetwork.MaxProcesses > 16384 {
			return errors.New("process_network.max_processes must be between 1 and 16384")
		}
		if c.ProcessNetwork.MaxSockets < 1 || c.ProcessNetwork.MaxSockets > 32768 {
			return errors.New("process_network.max_sockets must be between 1 and 32768")
		}
		if c.ProcessNetwork.MaxFileDescriptors < 1 || c.ProcessNetwork.MaxFileDescriptors > 262144 {
			return errors.New("process_network.max_file_descriptors must be between 1 and 262144")
		}
		if c.ProcessNetwork.MaxSockets > c.ProcessNetwork.MaxFileDescriptors {
			return errors.New("process_network.max_sockets cannot exceed max_file_descriptors")
		}
	}
	if c.EBPFSensor.Enabled {
		if c.EBPFSensor.RingBufferBytes < 1<<20 || c.EBPFSensor.RingBufferBytes > 64*1024*1024 || c.EBPFSensor.RingBufferBytes&(c.EBPFSensor.RingBufferBytes-1) != 0 {
			return errors.New("ebpf_sensor.ring_buffer_bytes must be a power of two between 1048576 and 67108864")
		}
		if c.EBPFSensor.MaxEventsPerSec < 100 || c.EBPFSensor.MaxEventsPerSec > 100000 {
			return errors.New("ebpf_sensor.max_events_per_sec must be between 100 and 100000")
		}
	}
	if c.PrivilegeSeparation.Enabled {
		if !filepath.IsAbs(c.PrivilegeSeparation.SensorSocket) || !filepath.IsAbs(c.PrivilegeSeparation.ResponseSocket) {
			return errors.New("privilege_separation socket paths must be absolute")
		}
		if c.PrivilegeSeparation.SensorSocket == c.PrivilegeSeparation.ResponseSocket {
			return errors.New("sensor and response helper sockets must be distinct")
		}
		if c.PrivilegeSeparation.MaxMessageBytes < 4096 || c.PrivilegeSeparation.MaxMessageBytes > 1024*1024 {
			return errors.New("privilege_separation.max_message_bytes must be between 4096 and 1048576")
		}
		timeout, err := time.ParseDuration(c.PrivilegeSeparation.RequestTimeout)
		if err != nil {
			return fmt.Errorf("invalid privilege_separation.request_timeout: %w", err)
		}
		if timeout < 100*time.Millisecond || timeout > time.Minute {
			return errors.New("privilege_separation.request_timeout must be between 100ms and 1m")
		}
	}
	if c.Detection.AuthFailureThreshold < 2 || c.Detection.AuthFailureThreshold > 100 {
		return errors.New("detection.auth_failure_threshold must be between 2 and 100")
	}
	authWindow, err := time.ParseDuration(c.Detection.AuthFailureWindow)
	if err != nil {
		return fmt.Errorf("invalid detection.auth_failure_window: %w", err)
	}
	if authWindow < 30*time.Second || authWindow > 24*time.Hour {
		return errors.New("detection.auth_failure_window must be between 30s and 24h")
	}
	if c.Protection.Enabled {
		if c.Protection.Mode != "audit" && c.Protection.Mode != "enforce" {
			return errors.New("protection.mode must be audit or enforce")
		}
		auditPeriod, err := time.ParseDuration(c.Protection.AuditPeriod)
		if err != nil || auditPeriod < 24*time.Hour || auditPeriod > 90*24*time.Hour {
			return errors.New("protection.audit_period must be between 24h and 2160h")
		}
		if c.Protection.SuspiciousThreshold < 1 || c.Protection.SuspiciousThreshold > 99 || c.Protection.MaliciousThreshold < 2 || c.Protection.MaliciousThreshold > 100 || c.Protection.SuspiciousThreshold >= c.Protection.MaliciousThreshold {
			return errors.New("protection thresholds must be ordered values between 1 and 100")
		}
		if len(c.Protection.ProtectedPaths) == 0 {
			return errors.New("protection.protected_paths must not be empty when protection is enabled")
		}
	}
	if c.Scanner.Enabled {
		quickInterval, quickErr := time.ParseDuration(c.Scanner.QuickInterval)
		fullInterval, fullErr := time.ParseDuration(c.Scanner.FullInterval)
		timeout, timeoutErr := time.ParseDuration(c.Scanner.ScanTimeout)
		if quickErr != nil || quickInterval < time.Hour || quickInterval > 30*24*time.Hour {
			return errors.New("scanner.quick_interval must be between 1h and 720h")
		}
		if fullErr != nil || fullInterval < 24*time.Hour || fullInterval > 90*24*time.Hour {
			return errors.New("scanner.full_interval must be between 24h and 2160h")
		}
		if timeoutErr != nil || timeout < time.Second || timeout > 10*time.Minute {
			return errors.New("scanner.scan_timeout must be between 1s and 10m")
		}
		if c.Scanner.Workers < 1 || c.Scanner.Workers > 8 {
			return errors.New("scanner.workers must be between 1 and 8")
		}
		if c.Scanner.MaxAutomaticFileBytes < 1024 || c.Scanner.MaxAutomaticFileBytes > 1024*1024*1024 || c.Scanner.MaxScheduledFileBytes < c.Scanner.MaxAutomaticFileBytes || c.Scanner.MaxScheduledFileBytes > 4*1024*1024*1024 {
			return errors.New("scanner file-size limits are invalid")
		}
		if c.Scanner.MaxFilesPerScan < 1 || c.Scanner.MaxFilesPerScan > 1000000 {
			return errors.New("scanner.max_files_per_scan must be between 1 and 1000000")
		}
	}
	if c.Reputation.Enabled {
		if err := validateHTTPSURL(c.Reputation.Endpoint, "reputation.endpoint"); err != nil {
			return err
		}
		if timeout, err := time.ParseDuration(c.Reputation.Timeout); err != nil || timeout < time.Second || timeout > 30*time.Second {
			return errors.New("reputation.timeout must be between 1s and 30s")
		}
		if ttl, err := time.ParseDuration(c.Reputation.CacheTTL); err != nil || ttl < time.Minute || ttl > 7*24*time.Hour {
			return errors.New("reputation.cache_ttl must be between 1m and 168h")
		}
	}
	if c.Retention.EvidenceDays < 1 || c.Retention.EvidenceDays > 3650 || c.Retention.QuarantineDays < 1 || c.Retention.QuarantineDays > 3650 {
		return errors.New("retention day limits must be between 1 and 3650")
	}
	if c.Retention.JournalSegmentBytes < 16*1024*1024 || c.Retention.JournalSegmentBytes > 4*1024*1024*1024 || c.Retention.EvidenceMaxBytes < c.Retention.JournalSegmentBytes || c.Retention.QuarantineMaxBytes < 1024*1024 {
		return errors.New("retention byte limits are invalid")
	}
	if c.Transport.Enabled {
		if strings.TrimSpace(c.TenantID) == "" {
			return errors.New("tenant_id is required when transport is enabled")
		}
		if err := validateHTTPSURL(c.Transport.Endpoint, "transport.endpoint"); err != nil {
			return err
		}
		if c.Transport.CertFile == "" || c.Transport.KeyFile == "" || c.Transport.CAFile == "" {
			return errors.New("transport cert_file, key_file, and ca_file are required")
		}
		timeout, err := time.ParseDuration(c.Transport.Timeout)
		if err != nil {
			return fmt.Errorf("invalid transport.timeout: %w", err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return errors.New("transport.timeout must be between 1s and 2m")
		}
		flushInterval, err := time.ParseDuration(c.Transport.FlushInterval)
		if err != nil {
			return fmt.Errorf("invalid transport.flush_interval: %w", err)
		}
		if flushInterval < 250*time.Millisecond || flushInterval > time.Minute {
			return errors.New("transport.flush_interval must be between 250ms and 1m")
		}
		if c.Transport.BatchSize < 1 || c.Transport.BatchSize > 1000 {
			return errors.New("transport.batch_size must be between 1 and 1000")
		}
		if c.Transport.PendingWarn < 100 || c.Transport.PendingWarn > 1000000 {
			return errors.New("transport.pending_warn must be between 100 and 1000000")
		}
		if c.Transport.AutoRenew {
			if err := validateHTTPSURL(c.Transport.RenewalEndpoint, "transport.renewal_endpoint"); err != nil {
				return err
			}
			renewBefore, err := time.ParseDuration(c.Transport.RenewBefore)
			if err != nil {
				return fmt.Errorf("invalid transport.renew_before: %w", err)
			}
			if renewBefore < time.Hour || renewBefore > 90*24*time.Hour {
				return errors.New("transport.renew_before must be between 1h and 2160h")
			}
			checkInterval, err := time.ParseDuration(c.Transport.RenewCheckInterval)
			if err != nil {
				return fmt.Errorf("invalid transport.renew_check_interval: %w", err)
			}
			if checkInterval < time.Minute || checkInterval > 24*time.Hour {
				return errors.New("transport.renew_check_interval must be between 1m and 24h")
			}
		}
	}
	if c.Central.Enabled {
		parsed, err := url.Parse(strings.TrimSpace(c.Central.URL))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.New("central.url must be an absolute HTTP(S) URL when Central is enabled")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("central.url must use http or https")
		}
		heartbeat, err := time.ParseDuration(c.Central.HeartbeatInterval)
		if err != nil {
			return fmt.Errorf("invalid central.heartbeat_interval: %w", err)
		}
		if heartbeat < 15*time.Second || heartbeat > 24*time.Hour {
			return errors.New("central.heartbeat_interval must be between 15s and 24h")
		}
		batch, err := time.ParseDuration(c.Central.BatchInterval)
		if err != nil {
			return fmt.Errorf("invalid central.batch_interval: %w", err)
		}
		if batch < time.Second || batch > time.Hour {
			return errors.New("central.batch_interval must be between 1s and 1h")
		}
		if c.Central.MaxBatch < 1 || c.Central.MaxBatch > 5000 {
			return errors.New("central.max_batch must be between 1 and 5000")
		}
		if c.Central.QueueSize < c.Central.MaxBatch || c.Central.QueueSize > 100000 {
			return errors.New("central.queue_size must be at least max_batch and no more than 100000")
		}
		if strings.TrimSpace(c.Central.APIKeyFile) == "" {
			return errors.New("central.api_key_file is required when Central is enabled")
		}
	}
	seen := map[string]struct{}{}
	for _, source := range c.Sources {
		if !source.Enabled {
			continue
		}
		if source.ID == "" || source.Path == "" || source.Format == "" {
			return errors.New("each enabled source requires id, path, and format")
		}
		if _, ok := seen[source.ID]; ok {
			return fmt.Errorf("duplicate source id %q", source.ID)
		}
		seen[source.ID] = struct{}{}
	}
	for _, source := range c.NativeSources {
		if !source.Enabled {
			continue
		}
		if !nativeSourceIDPattern.MatchString(source.ID) {
			return fmt.Errorf("native source id %q must match %s", source.ID, nativeSourceIDPattern.String())
		}
		if _, ok := seen[source.ID]; ok {
			return fmt.Errorf("duplicate source id %q", source.ID)
		}
		seen[source.ID] = struct{}{}
		if source.MaxBatch < 1 || source.MaxBatch > 5000 {
			return fmt.Errorf("native source %s max_batch must be between 1 and 5000", source.ID)
		}
		timeout, err := time.ParseDuration(source.CommandTimeout)
		if err != nil {
			return fmt.Errorf("native source %s command_timeout: %w", source.ID, err)
		}
		if timeout < time.Second || timeout > 2*time.Minute {
			return fmt.Errorf("native source %s command_timeout must be between 1s and 2m", source.ID)
		}
		switch source.Kind {
		case "windows_eventlog", "wineventlog", "sysmon":
			if !windowsChannelPattern.MatchString(source.Channel) {
				return fmt.Errorf("native source %s has invalid Windows event channel", source.ID)
			}
			if len(source.EventIDs) > 128 {
				return fmt.Errorf("native source %s supports at most 128 event IDs", source.ID)
			}
			for _, eventID := range source.EventIDs {
				if eventID < 1 || eventID > 65535 {
					return fmt.Errorf("native source %s has invalid event ID %d", source.ID, eventID)
				}
			}
		case "journald", "journalctl":
			if len(source.Units) > 32 || len(source.Identifiers) > 32 {
				return fmt.Errorf("native source %s supports at most 32 units and identifiers", source.ID)
			}
			for _, value := range append(append([]string{}, source.Units...), source.Identifiers...) {
				if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") {
					return fmt.Errorf("native source %s contains an invalid journald filter", source.ID)
				}
			}
		case "auditd", "linux_auditd":
			if source.Path == "" || !filepath.IsAbs(source.Path) {
				return fmt.Errorf("native source %s auditd path must be absolute", source.ID)
			}
			if source.MaxActiveSerials < 1 || source.MaxActiveSerials > 1024 {
				return fmt.Errorf("native source %s max_active_serials must be between 1 and 1024", source.ID)
			}
			if source.MaxRecordsPerSerial < 1 || source.MaxRecordsPerSerial > 1024 {
				return fmt.Errorf("native source %s max_records_per_serial must be between 1 and 1024", source.ID)
			}
			if source.MaxBytesPerSerial < 4096 || source.MaxBytesPerSerial > 1024*1024 {
				return fmt.Errorf("native source %s max_bytes_per_serial must be between 4096 and 1048576", source.ID)
			}
			// Active groups and finalized groups waiting for durable batch
			// acknowledgement both retain parsed untrusted evidence. Bound their
			// combined serialized input budget rather than only active serials.
			if int64(source.MaxActiveSerials+source.MaxBatch)*int64(source.MaxBytesPerSerial) > 32*1024*1024 {
				return fmt.Errorf("native source %s audit assembler and pending batch memory budget exceeds 32 MiB", source.ID)
			}
			assemblyTimeout, err := time.ParseDuration(source.AssemblyTimeout)
			if err != nil {
				return fmt.Errorf("invalid native source %s assembly_timeout: %w", source.ID, err)
			}
			if assemblyTimeout < 100*time.Millisecond || assemblyTimeout > 5*time.Minute {
				return fmt.Errorf("native source %s assembly_timeout must be between 100ms and 5m", source.ID)
			}
		default:
			return fmt.Errorf("native source %s has unsupported kind %q", source.ID, source.Kind)
		}
	}
	return nil
}

func validateHTTPSURL(value, name string) error {
	endpoint, err := url.Parse(strings.TrimSpace(value))
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return fmt.Errorf("%s must be an absolute https URL", name)
	}
	return nil
}

func EnsureAgentID(cfg *Config) error {
	if cfg.AgentID != "" {
		return nil
	}
	if err := EnsureDataDir(*cfg); err != nil {
		return err
	}
	identityPath := filepath.Join(cfg.DataDir, "agent.id")
	if content, err := os.ReadFile(identityPath); err == nil {
		identity := strings.TrimSpace(string(content))
		if !strings.HasPrefix(identity, "agent_") || len(identity) < 20 {
			return errors.New("persisted agent identity is invalid")
		}
		cfg.AgentID = identity
		return os.Chmod(identityPath, 0o600)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read persisted agent identity: %w", err)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate agent id: %w", err)
	}
	cfg.AgentID = "agent_" + hex.EncodeToString(buf)
	if err := os.WriteFile(identityPath, []byte(cfg.AgentID+"\n"), 0o600); err != nil {
		return fmt.Errorf("persist agent identity: %w", err)
	}
	return nil
}

func EnsureDataDir(cfg Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.Chmod(cfg.DataDir, 0o700)
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("ProgramData"); base != "" {
			return filepath.Join(base, "NTAgentShield")
		}
	}
	return "./data"
}
