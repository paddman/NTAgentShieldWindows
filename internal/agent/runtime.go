package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/ai"
	"github.com/paddman/NTAgentShieldWindows/internal/api"
	"github.com/paddman/NTAgentShieldWindows/internal/baseline"
	"github.com/paddman/NTAgentShieldWindows/internal/buildinfo"
	"github.com/paddman/NTAgentShieldWindows/internal/central"
	"github.com/paddman/NTAgentShieldWindows/internal/collector/filetail"
	"github.com/paddman/NTAgentShieldWindows/internal/collector/native"
	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/detection"
	"github.com/paddman/NTAgentShieldWindows/internal/enrollment"
	"github.com/paddman/NTAgentShieldWindows/internal/inventory"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/networkinventory"
	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
	"github.com/paddman/NTAgentShieldWindows/internal/protection"
	"github.com/paddman/NTAgentShieldWindows/internal/redact"
	ebpfsensor "github.com/paddman/NTAgentShieldWindows/internal/sensor/ebpf"
	"github.com/paddman/NTAgentShieldWindows/internal/sensoripc"
	"github.com/paddman/NTAgentShieldWindows/internal/store"
	"github.com/paddman/NTAgentShieldWindows/internal/transport"
)

type Runtime struct {
	cfg                      config.Config
	hostname                 string
	journal                  *store.Journal
	detector                 *detection.Engine
	tailers                  []*filetail.Tailer
	nativeSources            []native.Source
	inventoryCollector       *inventory.Collector
	baselineStore            *baseline.Store
	inventoryInterval        time.Duration
	processGraph             *processgraph.Graph
	processGraphInterval     time.Duration
	processNetwork           *networkinventory.Collector
	processNetworkInterval   time.Duration
	ebpfSensor               *ebpfsensor.Sensor
	ebpfHelper               *sensoripc.Client
	ebpfHelperHealthMu       sync.RWMutex
	ebpfHelperHealth         sensoripc.Health
	ebpfFallbackReason       string
	transportOutbox          *transport.Outbox
	transportSender          *transport.Sender
	transportFlushInterval   time.Duration
	logger                   *log.Logger
	startedAt                time.Time
	eventCount               atomic.Uint64
	findingCount             atomic.Uint64
	errorCount               atomic.Uint64
	inventoryCount           atomic.Uint64
	nativeEventCount         atomic.Uint64
	processGraphEventCount   atomic.Uint64
	processNetworkEventCount atomic.Uint64
	ebpfEventCount           atomic.Uint64
	transportSentCount       atomic.Uint64
	transportDeadLetterCount atomic.Uint64
	transportErrorCount      atomic.Uint64
	certificateRenewalCount  atomic.Uint64
	lastInventoryNano        atomic.Int64
	lastProcessGraphNano     atomic.Int64
	lastProcessNetworkNano   atomic.Int64
	lastTransportSuccessNano atomic.Int64
	lastCertificateRenewNano atomic.Int64
	central                  *central.Client
	protection               *protection.Controller
	aiClient                 *ai.Client
	aiQueue                  chan aiJob
	aiMinInterval            time.Duration
	aiRequests               atomic.Uint64
	aiSuccesses              atomic.Uint64
	aiFailures               atomic.Uint64
	aiDropped                atomic.Uint64
	lastAIStartNano          atomic.Int64
	lastAISuccessNano        atomic.Int64
	aiAuditMu                sync.RWMutex
	aiRecent                 []AIAuditEntry
	aiLastError              string
}

type Status struct {
	Status                   string             `json:"status"`
	AgentID                  string             `json:"agent_id"`
	TenantID                 string             `json:"tenant_id,omitempty"`
	Hostname                 string             `json:"hostname"`
	StartedAt                time.Time          `json:"started_at"`
	Uptime                   string             `json:"uptime"`
	Events                   uint64             `json:"events"`
	Findings                 uint64             `json:"findings"`
	Errors                   uint64             `json:"errors"`
	Sources                  int                `json:"sources"`
	FileSources              int                `json:"file_sources"`
	NativeSources            int                `json:"native_sources"`
	NativeEvents             uint64             `json:"native_events"`
	AuditActiveSerials       int                `json:"audit_active_serials"`
	AuditAssembledEvents     uint64             `json:"audit_assembled_events"`
	AuditIncompleteGroups    uint64             `json:"audit_incomplete_groups"`
	AuditDroppedRecords      uint64             `json:"audit_dropped_records"`
	AIEnabled                bool               `json:"ai_enabled"`
	AI                       AIStatus           `json:"ai"`
	InventoryEnabled         bool               `json:"inventory_enabled"`
	InventoryRuns            uint64             `json:"inventory_runs"`
	ProcessGraphEnabled      bool               `json:"process_graph_enabled"`
	ProcessGraphEvents       uint64             `json:"process_graph_events"`
	ProcessGraphActive       int                `json:"process_graph_active"`
	ProcessGraphExited       int                `json:"process_graph_exited"`
	ProcessGraphReconciles   uint64             `json:"process_graph_reconciliations"`
	LastProcessGraphAt       *time.Time         `json:"last_process_graph_at,omitempty"`
	ProcessNetworkEnabled    bool               `json:"process_network_enabled"`
	ProcessNetworkEvents     uint64             `json:"process_network_events"`
	ProcessNetworkSockets    int                `json:"process_network_sockets"`
	ProcessNetworkScans      uint64             `json:"process_network_scans"`
	ProcessNetworkWarnings   uint64             `json:"process_network_warnings"`
	LastProcessNetworkAt     *time.Time         `json:"last_process_network_at,omitempty"`
	EBPFSensorEnabled        bool               `json:"ebpf_sensor_enabled"`
	EBPFEvents               uint64             `json:"ebpf_events"`
	EBPFLoadedPrograms       int                `json:"ebpf_loaded_programs"`
	EBPFAttachedHooks        int                `json:"ebpf_attached_hooks"`
	EBPFRingBufferLoss       uint64             `json:"ebpf_ring_buffer_loss"`
	EBPFParseErrors          uint64             `json:"ebpf_parse_errors"`
	EBPFEventsPerSecond      uint64             `json:"ebpf_events_per_second"`
	EBPFThrottledEvents      uint64             `json:"ebpf_throttled_events"`
	EBPFLastEventAt          *time.Time         `json:"ebpf_last_event_at,omitempty"`
	EBPFFallbackReason       string             `json:"ebpf_fallback_reason,omitempty"`
	EBPFHelperQueueLoss      uint64             `json:"ebpf_helper_queue_loss"`
	LastInventoryAt          *time.Time         `json:"last_inventory_at,omitempty"`
	InventoryInterval        string             `json:"inventory_interval,omitempty"`
	TransportEnabled         bool               `json:"transport_enabled"`
	TransportPending         int                `json:"transport_pending"`
	TransportPendingBytes    int64              `json:"transport_pending_bytes"`
	TransportDeadLetter      int                `json:"transport_dead_letter"`
	TransportDeadLetterBytes int64              `json:"transport_dead_letter_bytes"`
	TransportSent            uint64             `json:"transport_sent"`
	TransportErrors          uint64             `json:"transport_errors"`
	TransportBackpressure    bool               `json:"transport_backpressure"`
	LastTransportSuccessAt   *time.Time         `json:"last_transport_success_at,omitempty"`
	CertificateAutoRenew     bool               `json:"certificate_auto_renew"`
	CertificateExpiresAt     *time.Time         `json:"certificate_expires_at,omitempty"`
	CertificateRenewals      uint64             `json:"certificate_renewals"`
	LastCertificateRenewAt   *time.Time         `json:"last_certificate_renew_at,omitempty"`
	Build                    buildinfo.Info     `json:"build"`
	SafetyModel              string             `json:"safety_model"`
	Protection               *protection.Status `json:"protection,omitempty"`
}

func New(cfg config.Config, logger *log.Logger) (*Runtime, error) {
	if logger == nil {
		logger = log.New(os.Stdout, "ntagentshield ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	}
	if err := config.EnsureDataDir(cfg); err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	journal, err := store.Open(filepath.Join(cfg.DataDir, "evidence.journal.jsonl"))
	if err != nil {
		return nil, err
	}
	authFailureWindow, err := time.ParseDuration(cfg.Detection.AuthFailureWindow)
	if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("initialize authentication-failure window: %w", err)
	}
	runtime := &Runtime{
		cfg:      cfg,
		hostname: hostname,
		journal:  journal,
		detector: detection.NewWithOptions(detection.Options{
			AuthFailureThreshold: cfg.Detection.AuthFailureThreshold,
			AuthFailureWindow:    authFailureWindow,
		}),
		logger:    logger,
		startedAt: time.Now().UTC(),
	}
	if cfg.AI.Enabled {
		client, err := ai.New(cfg.AI)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize AI investigator: %w", err)
		}
		runtime.aiClient = client
		if cfg.AI.AutoAnalyze {
			interval, err := time.ParseDuration(cfg.AI.MinInterval)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize AI rate limit: %w", err)
			}
			runtime.aiQueue = make(chan aiJob, cfg.AI.QueueSize)
			runtime.aiMinInterval = interval
		}
	}
	for _, source := range cfg.Sources {
		if !source.Enabled {
			continue
		}
		tailer, err := filetail.New(source)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize source %s: %w", source.ID, err)
		}
		runtime.tailers = append(runtime.tailers, tailer)
	}
	for _, sourceConfig := range cfg.NativeSources {
		if !sourceConfig.Enabled {
			continue
		}
		source, err := native.New(sourceConfig, cfg.DataDir)
		if errors.Is(err, native.ErrUnsupportedPlatform) {
			logger.Printf("native source skipped id=%s kind=%s reason=%v", sourceConfig.ID, sourceConfig.Kind, err)
			continue
		}
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize native source %s: %w", sourceConfig.ID, err)
		}
		runtime.nativeSources = append(runtime.nativeSources, source)
	}
	if cfg.Inventory.Enabled {
		interval, err := time.ParseDuration(cfg.Inventory.Interval)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory interval: %w", err)
		}
		timeout, err := time.ParseDuration(cfg.Inventory.CommandTimeout)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory command timeout: %w", err)
		}
		collector, err := inventory.New(inventory.Options{
			IncludeProcesses: cfg.Inventory.IncludeProcesses,
			IncludeServices:  cfg.Inventory.IncludeServices,
			IncludeListeners: cfg.Inventory.IncludeListeners,
			IncludeSoftware:  cfg.Inventory.IncludeSoftware,
			MaxItems:         cfg.Inventory.MaxItems,
			CommandTimeout:   timeout,
		})
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize inventory: %w", err)
		}
		baselineStore, err := baseline.New(cfg.DataDir)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize signed inventory baseline: %w", err)
		}
		storedBaseline, exists, err := baselineStore.Load()
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("load signed inventory baseline: %w", err)
		}
		if exists {
			runtime.detector.SeedInventoryBaseline(storedBaseline)
			logger.Printf("verified persistent signed inventory baseline loaded")
		}
		runtime.inventoryCollector = collector
		runtime.baselineStore = baselineStore
		runtime.inventoryInterval = interval
	}
	if cfg.ProcessGraph.Enabled && goruntime.GOOS == "linux" {
		interval, err := time.ParseDuration(cfg.ProcessGraph.ReconcileInterval)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize process graph interval: %w", err)
		}
		graph, err := processgraph.Open(processgraph.Options{
			StatePath:              filepath.Join(cfg.DataDir, "process-graph.json"),
			MaxProcesses:           cfg.ProcessGraph.MaxProcesses,
			MaxExitedProcesses:     cfg.ProcessGraph.MaxExitedProcesses,
			MaxCommandLineBytes:    cfg.ProcessGraph.MaxCommandLineBytes,
			MaxExecutableHashBytes: cfg.ProcessGraph.MaxExecutableHashBytes,
		})
		if err != nil {
			// A protected or unavailable /proc must not prevent the unprivileged
			// core agent from running its other collectors. The graph is simply
			// unavailable until permissions or the kernel view are repaired.
			logger.Printf("Linux process graph unavailable: %v", err)
		} else {
			runtime.processGraph = graph
			runtime.processGraphInterval = interval
		}
	}
	if cfg.ProcessNetwork.Enabled && goruntime.GOOS == "linux" {
		if runtime.processGraph == nil {
			logger.Printf("Linux process network attribution unavailable: process graph is not available")
		} else {
			interval, err := time.ParseDuration(cfg.ProcessNetwork.ReconcileInterval)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize process network interval: %w", err)
			}
			collector, err := networkinventory.New(runtime.processGraph, networkinventory.Options{
				MaxProcesses: cfg.ProcessNetwork.MaxProcesses,
				MaxSockets:   cfg.ProcessNetwork.MaxSockets,
				MaxFDs:       cfg.ProcessNetwork.MaxFileDescriptors,
			})
			if err != nil {
				logger.Printf("Linux process network attribution unavailable: %v", err)
			} else {
				runtime.processNetwork = collector
				runtime.processNetworkInterval = interval
			}
		}
	}
	if cfg.EBPFSensor.Enabled && goruntime.GOOS == "linux" {
		if cfg.PrivilegeSeparation.Enabled {
			timeout, err := time.ParseDuration(cfg.PrivilegeSeparation.RequestTimeout)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize sensor helper timeout: %w", err)
			}
			// Reuse the bounded collector interval while the sensor queue is idle.
			// A non-empty queue is drained without waiting, so this limits idle IPC
			// audit volume without throttling an active event stream.
			client, err := sensoripc.NewClient(cfg.PrivilegeSeparation.SensorSocket, cfg.PrivilegeSeparation.MaxMessageBytes, 32, timeout, cfg.PollInterval)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize sensor helper client: %w", err)
			}
			runtime.ebpfHelper = client
		} else if runtime.processGraph == nil {
			runtime.ebpfFallbackReason = "process graph is unavailable"
			logger.Printf("Linux eBPF sensor unavailable: process graph is not available; auditd/journald fallback continues")
		} else {
			sensor, err := ebpfsensor.New(runtime.processGraph, ebpfsensor.Options{RingBufferBytes: cfg.EBPFSensor.RingBufferBytes, MaxEventsPerSec: cfg.EBPFSensor.MaxEventsPerSec})
			if err != nil {
				rßnõ¶‰ËkºwµçQ•áĞ¤ì(%™½È|°Ñ…¥±•È€èôÉ…¹”È¹Ñ…¥±•ÉÌì($%¥˜•ÉÈ€èôÑà¹ÉÈ ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸($%ô($%•Ù•¹ÑÌ°•ÉÉÌ€èôÑ…¥±•È¹A½±° ¤($%™½È|°•ÉÈ€èôÉ…¹”•ÉÉÌì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰™¥±”µÑ…¥°ˆ°•ÉÈ¤($%ô($%™½È|°•Ù•¹Ğ€èôÉ…¹”•Ù•¹ÑÌì($$%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$$%È¹•ÉÉ½É½Õ¹Ğ¹‘ Ä¤($$$%È¹±½•È¹AÉ¥¹Ñ˜ ‰•Ù•¹ĞÁÉ½•ÍÍ¥¹œ•ÉÉ½Èè€•Øˆ°•ÉÈ¤($$%ô($%ô(%ô)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤Á½±±9…Ñ¥Ù”¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ¤ì(%™½È|°Í½ÕÉ”€èôÉ…¹”È¹¹…Ñ¥Ù•M½ÕÉ•Ìì($%¥˜•ÉÈ€èôÑà¹ÉÈ ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸($%ô($%‰…Ñ °•ÉÉÌ€èôÍ½ÕÉ”¹A½±°¡Ñà¤($%™½È|°•ÉÈ€èôÉ…¹”•ÉÉÌì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È¡Í½ÕÉ”¹-¥¹ ¤¬ˆ¼ˆ­Í½ÕÉ”¹% ¤°•ÉÈ¤($%ô($%ÁÉ½•ÍÍ•€èôÑÉÕ”($%™½È|°•Ù•¹Ğ€èôÉ…¹”‰…Ñ ¹Ù•¹ÑÌì($$%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$$%ÁÉ½•ÍÍ•€ô™…±Í”($$$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È¡Í½ÕÉ”¹-¥¹ ¤¬ˆ¼ˆ­Í½ÕÉ”¹% ¤°•ÉÈ¤($$$%‰É•…¬($$%ô($$%È¹¹…Ñ¥Ù•Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤($%ô($%¥˜ÁÉ½•ÍÍ•ì($$%¥˜•ÉÈ€èô‰…Ñ ¹­¹½İ±•‘” ¤ì•ÉÈ€„ô¹¥°ì($$$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È¡Í½ÕÉ”¹-¥¹ ¤¬ˆ¼ˆ­Í½ÕÉ”¹% ¤¬ˆ½ÕÉÍ½Èˆ°•ÉÈ¤($$%ô($%ô(%ô)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤½±±•Ñ%¹Ù•¹Ñ½Éä¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ°™½É”‰½½°¤ì(%¥˜È¹¥¹Ù•¹Ñ½Éå½±±•Ñ½È€ôô¹¥°ñğÑà¹ÉÈ ¤€„ô¹¥°ì($%É•ÑÕÉ¸(%ô(%±…ÍÑ9…¹¼€èôÈ¹±…ÍÑ%¹Ù•¹Ñ½Éå9…¹¼¹1½… ¤(%¥˜€…™½É”€˜˜±…ÍÑ9…¹¼€„ô€À€˜˜Ñ¥µ”¹M¥¹”¡Ñ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¤€ğÈ¹¥¹Ù•¹Ñ½Éå%¹Ñ•ÉÙ…°ì($%É•ÑÕÉ¸(%ô(%•Ù•¹Ğ°•ÉÈ€èôÈ¹¥¹Ù•¹Ñ½Éå½±±•Ñ½È¹Ù•¹Ğ¡Ñà¤(%¥˜•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰¹…Ñ¥Ù”µ¥¹Ù•¹Ñ½Éäˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%É•‘…Ğ¹Ù•¹Ğ ™•Ù•¹Ğ¤(%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰¹…Ñ¥Ù”µ¥¹Ù•¹Ñ½Éäˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%¥˜È¹‰…Í•±¥¹•MÑ½É”€„ô¹¥°ì($%Í¹…ÁÍ¡½Ğ°•ÉÈ€èô‰…Í•±¥¹”¹M¹…ÁÍ¡½ÑÉ½µÙ•¹Ğ¡•Ù•¹Ğ¤($%¥˜•ÉÈ€„ô¹¥°ì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰¥¹Ù•¹Ñ½Éäµ‰…Í•±¥¹”ˆ°•ÉÈ¤($$%É•ÑÕÉ¸($%ô($%¥˜•ÉÈ€èôÈ¹‰…Í•±¥¹•MÑ½É”¹M…Ù”¡Í¹…ÁÍ¡½Ğ¤ì•ÉÈ€„ô¹¥°ì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰¥¹Ù•¹Ñ½Éäµ‰…Í•±¥¹”ˆ°•ÉÈ¤($$%É•ÑÕÉ¸($%ô(%ô(%½±±•Ñ•‘Ğ€èôÑ¥µ”¹9½Ü ¤¹UQ ¤(%È¹±…ÍÑ%¹Ù•¹Ñ½Éå9…¹¼¹MÑ½É”¡½±±•Ñ•‘Ğ¹U¹¥á9…¹¼ ¤¤(%È¹¥¹Ù•¹Ñ½Éå½Õ¹Ğ¹‘ Ä¤(%È¹±½•È¹AÉ¥¹Ñ˜ ‰…ÍÍ•Ğ¥¹Ù•¹Ñ½Éä½±±•Ñ•ÁÉ½•ÍÍ•Ìô•ĞÍ•ÉÙ¥•Ìô•Ğ±¥ÍÑ•¹•ÉÌô•ĞÍ½™Ñİ…É”ô•Ğˆ°È¹™œ¹%¹Ù•¹Ñ½Éä¹%¹±Õ‘•AÉ½•ÍÍ•Ì°È¹™œ¹%¹Ù•¹Ñ½Éä¹%¹±Õ‘•M•ÉÙ¥•Ì°È¹™œ¹%¹Ù•¹Ñ½Éä¹%¹±Õ‘•1¥ÍÑ•¹•ÉÌ°È¹™œ¹%¹Ù•¹Ñ½Éä¹%¹±Õ‘•M½™Ñİ…É”¤)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤½±±•ÑAÉ½•ÍÍÉ…Á ¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ°™½É”‰½½°¤ì(%¥˜È¹ÁÉ½•ÍÍÉ…Á €ôô¹¥°ñğÑà¹ÉÈ ¤€„ô¹¥°ì($%É•ÑÕÉ¸(%ô(%±…ÍÑ9…¹¼€èôÈ¹±…ÍÑAÉ½•ÍÍÉ…Á¡9…¹¼¹1½… ¤(%¥˜€…™½É”€˜˜±…ÍÑ9…¹¼€„ô€À€˜˜Ñ¥µ”¹M¥¹”¡Ñ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¤€ğÈ¹ÁÉ½•ÍÍÉ…Á¡%¹Ñ•ÉÙ…°ì($%É•ÑÕÉ¸(%ô(%‰…Ñ °•ÉÈ€èôÈ¹ÁÉ½•ÍÍÉ…Á ¹I•½¹¥±”¡Ñà¤(%¥˜•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµÉ…Á ˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%™½È|°•Ù•¹Ğ€èôÉ…¹”‰…Ñ ¹Ù•¹ÑÌì($%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµÉ…Á ˆ°•ÉÈ¤($$%É•ÑÕÉ¸($%ô($%È¹ÁÉ½•ÍÍÉ…Á¡Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤(%ô(%¥˜•ÉÈ€èô‰…Ñ ¹­¹½İ±•‘” ¤ì•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµÉ…Á ½¡•­Á½¥¹Ğˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%È¹±…ÍÑAÉ½•ÍÍÉ…Á¡9…¹¼¹MÑ½É”¡Ñ¥µ”¹9½Ü ¤¹UQ ¤¹U¹¥á9…¹¼ ¤¤)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤½±±•ÑAÉ½•ÍÍ9•Ñİ½É¬¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ°™½É”‰½½°¤ì(%¥˜È¹ÁÉ½•ÍÍ9•Ñİ½É¬€ôô¹¥°ñğÑà¹ÉÈ ¤€„ô¹¥°ì($%É•ÑÕÉ¸(%ô(%±…ÍÑ9…¹¼€èôÈ¹±…ÍÑAÉ½•ÍÍ9•Ñİ½É­9…¹¼¹1½… ¤(%¥˜€…™½É”€˜˜±…ÍÑ9…¹¼€„ô€À€˜˜Ñ¥µ”¹M¥¹”¡Ñ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¤€ğÈ¹ÁÉ½•ÍÍ9•Ñİ½É­%¹Ñ•ÉÙ…°ì($%É•ÑÕÉ¸(%ô(%‰…Ñ °•ÉÈ€èôÈ¹ÁÉ½•ÍÍ9•Ñİ½É¬¹I•½¹¥±”¡Ñà¤(%¥˜•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµ¹•Ñİ½É¬ˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%™½È|°•Ù•¹Ğ€èôÉ…¹”‰…Ñ ¹Ù•¹ÑÌì($%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµ¹•Ñİ½É¬ˆ°•ÉÈ¤($$%É•ÑÕÉ¸($%ô($%È¹ÁÉ½•ÍÍ9•Ñİ½É­Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤(%ô(%¥˜•ÉÈ€èô‰…Ñ ¹­¹½İ±•‘” ¤ì•ÉÈ€„ô¹¥°ì($%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰±¥¹ÕàµÁÉ½•ÍÌµ¹•Ñİ½É¬½¡•­Á½¥¹Ğˆ°•ÉÈ¤($%É•ÑÕÉ¸(%ô(%È¹±…ÍÑAÉ½•ÍÍ9•Ñİ½É­9…¹¼¹MÑ½É”¡Ñ¥µ”¹9½Ü ¤¹UQ ¤¹U¹¥á9…¹¼ ¤¤)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤ÍÑ…ÉÑ	AM•¹Í½È¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ¤ì(%¥˜È¹•‰Á™!•±Á•È€„ô¹¥°ì($%¼È¹ÉÕ¹M•¹Í½É!•±Á•È¡Ñà¤($%É•ÑÕÉ¸(%ô(%¥˜È¹•‰Á™M•¹Í½È€ôô¹¥°ì($%É•ÑÕÉ¸(%ô(%¥˜•ÉÈ€èôÈ¹•‰Á™M•¹Í½È¹MÑ…ÉĞ¡Ñà°™Õ¹Œ¡•Ù•¹Ğµ½‘•°¹Ù•¹Ğ¤•ÉÉ½Èì($%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸•ÉÈ($%ô($%È¹•‰Á™Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤($%É•ÑÕÉ¸¹¥°(%ô¤ì•ÉÈ€„ô¹¥°ì($%È¹±½•È¹AÉ¥¹Ñ˜ ‰1¥¹Õà•	AÍ•¹Í½ÈÕ¹…Ù…¥±…‰±”è€•Øì…Õ‘¥Ñ½©½ÕÉ¹…±™…±±‰…¬½¹Ñ¥¹Õ•Ìˆ°•ÉÈ¤(%ô)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤ÉÕ¹M•¹Í½É!•±Á•È¡Ñà½¹Ñ•áĞ¹½¹Ñ•áĞ¤ì(%±…ÍÑÉÉ½È€èô€ˆˆ(%™½ÈÑà¹ÉÈ ¤€ôô¹¥°ì($%•ÉÈ€èôÈ¹•‰Á™!•±Á•È¹IÕ¸¡Ñà°™Õ¹Œ¡•Ù•¹Ğµ½‘•°¹Ù•¹Ğ¤•ÉÉ½Èì($$%¥˜|°•ÉÈ€èôÈ¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸•ÉÈ($$%ô($$%È¹•‰Á™Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤($$%É•ÑÕÉ¸¹¥°($%ô°™Õ¹Œ¡¡•…±Ñ Í•¹Í½É¥ÁŒ¹!•…±Ñ ¤ì($$%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹1½¬ ¤($$%È¹•‰Á™!•±Á•É!•…±Ñ €ô¡•…±Ñ ($$%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹U¹±½¬ ¤($%ô¤($%¥˜Ñà¹ÉÈ ¤€„ô¹¥°ì($$%É•ÑÕÉ¸($%ô($%µ•ÍÍ…”€èô€‰Í•¹Í½È¡•±Á•ÈÍÑ½ÁÁ•ˆ($%¥˜•ÉÈ€„ô¹¥°ì($$%µ•ÍÍ…”€ô•ÉÈ¹ÉÉ½È ¤($%ô($%¥˜µ•ÍÍ…”€„ô±…ÍÑÉÉ½Èì($$%È¹±½•È¹AÉ¥¹Ñ˜ ‰1¥¹ÕàÍ•¹Í½È¡•±Á•ÈÕ¹…Ù…¥±…‰±”è€•Øì…Õ‘¥Ñ½©½ÕÉ¹…±™…±±‰…¬½¹Ñ¥¹Õ•Ìˆ°•ÉÈ¤($$%±…ÍÑÉÉ½È€ôµ•ÍÍ…”($%ô($%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹1½¬ ¤($%È¹•‰Á™!•±Á•É!•…±Ñ ¹M•¹Í½È¹¹…‰±•€ô™…±Í”($%È¹•‰Á™!•±Á•É!•…±Ñ ¹M•¹Í½È¹…±±‰…­I•…Í½¸€ôµ•ÍÍ…”($%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹U¹±½¬ ¤($%Ñ¥µ•È€èôÑ¥µ”¹9•İQ¥µ•È È€¨Ñ¥µ”¹M•½¹¤($%Í•±•Ğì($%…Í”€ğµÑà¹½¹” ¤è($$%Ñ¥µ•È¹MÑ½À ¤($$%É•ÑÕÉ¸($%…Í”€ğµÑ¥µ•È¹è($%ô(%ô)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤É•½É‘½±±•Ñ½ÉÉÉ½È¡½±±•Ñ½ÈÍÑÉ¥¹œ°•ÉÈ•ÉÉ½È¤ì(%¥˜•ÉÈ€ôô¹¥°ì($%É•ÑÕÉ¸(%ô(%È¹•ÉÉ½É½Õ¹Ğ¹‘ Ä¤(%È¹±½•È¹AÉ¥¹Ñ˜ ‰½±±•Ñ½È•ÉÉ½È½±±•Ñ½Èô•Ì•ÉÉ½Èô•Øˆ°½±±•Ñ½È°•ÉÈ¤(%|°|€ôÈ¹©½ÕÉ¹…°¹ÁÁ•¹ ‰½±±•Ñ½È¹•ÉÉ½Èˆ°µ…ÁmÍÑÉ¥¹uÍÑÉ¥¹ì‰½±±•Ñ½Èˆè½±±•Ñ½È°€‰•ÉÉ½Èˆè•ÉÈ¹ÉÉ½È ¥ô¤)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤%¹•ÍĞ¡|½¹Ñ•áĞ¹½¹Ñ•áĞ°•Ù•¹Ğµ½‘•°¹Ù•¹Ğ¤€¡muµ½‘•°¹¥¹‘¥¹œ°•ÉÉ½È¤ì(%É•ÑÕÉ¸È¹ÁÉ½•ÍÌ¡•Ù•¹Ğ¤)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤ÁÉ½•ÍÌ¡•Ù•¹Ğµ½‘•°¹Ù•¹Ğ¤€¡muµ½‘•°¹¥¹‘¥¹œ°•ÉÉ½È¤ì(%¥˜È¹ÁÉ½•ÍÍÉ…Á €„ô¹¥°ì($%È¹ÁÉ½•ÍÍÉ…Á ¹¹É¥  ™•Ù•¹Ğ¤(%ô(%•Ù•¹Ğ¹AÉ•Á…É” ¤(%•Ù•¹Ğ¹•¹Ñ%€ôÈ¹™œ¹•¹Ñ%(%•Ù•¹Ğ¹Q•¹…¹Ñ%€ôÈ¹™œ¹Q•¹…¹Ñ%(%¥˜•Ù•¹Ğ¹ÍÍ•Ğ¹!½ÍÑ¹…µ”€ôô€ˆˆì($%•Ù•¹Ğ¹ÍÍ•Ğ¹!½ÍÑ¹…µ”€ôÈ¹¡½ÍÑ¹…µ”(%ô(%É•‘…Ğ¹Ù•¹Ğ ™•Ù•¹Ğ¤(%¥˜|°•ÉÈ€èôÈ¹©½ÕÉ¹…°¹ÁÁ•¹ ‰•Ù•¹Ğˆ°•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸¹¥°°•ÉÈ(%ô(%È¹•Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤(%™¥¹‘¥¹Ì€èôÈ¹‘•Ñ•Ñ½È¹%¹ÍÁ•Ğ¡•Ù•¹Ğ¤(%™½È|°™¥¹‘¥¹œ€èôÉ…¹”™¥¹‘¥¹Ìì($%¥˜|°•ÉÈ€èôÈ¹©½ÕÉ¹…°¹ÁÁ•¹ ‰™¥¹‘¥¹œˆ°™¥¹‘¥¹œ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™¥¹‘¥¹Ì°•ÉÈ($%ô($%È¹™¥¹‘¥¹½Õ¹Ğ¹‘ Ä¤($%•¹½‘•°|€èô©Í½¸¹5…ÉÍ¡…°¡™¥¹‘¥¹œ¤($%È¹±½•È¹AÉ¥¹Ñ˜ ‰™¥¹‘¥¹œ€•Ìˆ°•¹½‘•¤(%ô(%¥˜È¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à€„ô¹¥°ì($%¥˜•ÉÈ€èôÈ¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à¹¹ÅÕ•Õ”¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸™¥¹‘¥¹Ì°™µĞ¹ÉÉ½É˜ ‰ÅÕ•Õ”Ñ•±•µ•ÑÉä™½È½¹ÑÉ½°A±…¹”è€•Üˆ°•ÉÈ¤($%ô(%ô(%¥˜È¹•¹ÑÉ…°€„ô¹¥°ì($%È¹•¹ÑÉ…°¹¹ÅÕ•Õ”¡•Ù•¹Ğ°™¥¹‘¥¹Ì¤(%ô(%È¹•¹ÅÕ•Õ•$¡•Ù•¹Ğ°™¥¹‘¥¹Ì¤(%¥˜È¹ÁÉ½Ñ•Ñ¥½¸€„ô¹¥°ì($%½ÕÑ½µ”°É•Á½ÉĞ°•ÉÈ€èôÈ¹ÁÉ½Ñ•Ñ¥½¸¹%¹ÍÁ•ÑÙ•¹Ğ¡½¹Ñ•áĞ¹	…­É½Õ¹ ¤°•Ù•¹Ğ¤($%¥˜•ÉÈ€„ô¹¥°ì($$%È¹É•½É‘½±±•Ñ½ÉÉÉ½È ‰İ¥¹‘½İÌµÁÉ½Ñ•Ñ¥½¸½ÁÉ½•ÍÌˆ°•ÉÈ¤($%ô•±Í”¥˜É•Á½ÉĞì($$%¥˜•ÉÈ€èôÈ¹É•½É‘AÉ½Ñ•Ñ¥½¹=ÕÑ½µ”¡½ÕÑ½µ”¤ì•ÉÈ€„ô¹¥°ì($$$%É•ÑÕÉ¸™¥¹‘¥¹Ì°•ÉÈ($$%ô($$%¥˜½ÕÑ½µ”¹¥¹‘¥¹œ€„ô¹¥°ì($$$%™¥¹‘¥¹Ì€ô…ÁÁ•¹¡™¥¹‘¥¹Ì°€©½ÕÑ½µ”¹¥¹‘¥¹œ¤($$%ô($%ô(%ô(%É•ÑÕÉ¸™¥¹‘¥¹Ì°¹¥°)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤É•½É‘AÉ½Ñ•Ñ¥½¹=ÕÑ½µ”¡½ÕÑ½µ”ÁÉ½Ñ•Ñ¥½¸¹=ÕÑ½µ”¤•ÉÉ½Èì(%¥˜½ÕÑ½µ”¹Ù•¹Ğ€ôô¹¥°ì($%É•ÑÕÉ¸¹¥°(%ô(%•Ù•¹Ğ€èô€©½ÕÑ½µ”¹Ù•¹Ğ(%•Ù•¹Ğ¹•¹Ñ%€ôÈ¹™œ¹•¹Ñ%(%•Ù•¹Ğ¹Q•¹…¹Ñ%€ôÈ¹™œ¹Q•¹…¹Ñ%(%¥˜•Ù•¹Ğ¹ÍÍ•Ğ¹!½ÍÑ¹…µ”€ôô€ˆˆì($%•Ù•¹Ğ¹ÍÍ•Ğ¹!½ÍÑ¹…µ”€ôÈ¹¡½ÍÑ¹…µ”(%ô(%•Ù•¹Ğ¹AÉ•Á…É” ¤(%É•‘…Ğ¹Ù•¹Ğ ™•Ù•¹Ğ¤(%¥˜|°•ÉÈ€èôÈ¹©½ÕÉ¹…°¹ÁÁ•¹ ‰•Ù•¹Ğˆ°•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($%É•ÑÕÉ¸•ÉÈ(%ô(%È¹•Ù•¹Ñ½Õ¹Ğ¹‘ Ä¤(%™¥¹‘¥¹Ì€èômuµ½‘•°¹¥¹‘¥¹íô(%¥˜½ÕÑ½µ”¹¥¹‘¥¹œ€„ô¹¥°ì($%™¥¹‘¥¹œ€èô€©½ÕÑ½µ”¹¥¹‘¥¹œ($%™¥¹‘¥¹œ¹•¹Ñ%€ôÈ¹™œ¹•¹Ñ%($%™¥¹‘¥¹œ¹Q•¹…¹Ñ%€ôÈ¹™œ¹Q•¹…¹Ñ%($%™¥¹‘¥¹œ¹ÍÍ•Ğ€ô•Ù•¹Ğ¹ÍÍ•Ğ($%™¥¹‘¥¹œ¹Ù¥‘•¹•Ù•¹Ñ%Ì€ômuÍÑÉ¥¹í•Ù•¹Ğ¹%ô($%¥˜™¥¹‘¥¹œ¹ÑÑÉ¥‰ÕÑ•Ì€ôô¹¥°ì($$%™¥¹‘¥¹œ¹ÑÑÉ¥‰ÕÑ•Ì€ôµ…ÁmÍÑÉ¥¹u¥¹Ñ•É™…•íõíô($%ô($%™¥¹‘¥¹œ¹ÑÑÉ¥‰ÕÑ•Íl‰…Ñ¥½¹Ì‰t€ô½ÕÑ½µ”¹Ñ¥½¹Ì($%¥˜|°•ÉÈ€èôÈ¹©½ÕÉ¹…°¹ÁÁ•¹ ‰™¥¹‘¥¹œˆ°™¥¹‘¥¹œ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸•ÉÈ($%ô($%È¹™¥¹‘¥¹½Õ¹Ğ¹‘ Ä¤($%™¥¹‘¥¹Ì€ô…ÁÁ•¹¡™¥¹‘¥¹Ì°™¥¹‘¥¹œ¤(%ô(%¥˜È¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à€„ô¹¥°ì($%¥˜•ÉÈ€èôÈ¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à¹¹ÅÕ•Õ”¡•Ù•¹Ğ¤ì•ÉÈ€„ô¹¥°ì($$%É•ÑÕÉ¸•ÉÈ($%ô(%ô(%¥˜È¹•¹ÑÉ…°€„ô¹¥°ì($%È¹•¹ÑÉ…°¹¹ÅÕ•Õ”¡•Ù•¹Ğ°™¥¹‘¥¹Ì¤(%ô(%É•ÑÕÉ¸¹¥°)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤•¹ÑÉ…±MÑ…ÑÕÌ ¤•¹ÑÉ…°¹!•…ÉÑ‰•…ÑMÑ…ÑÕÌì(%ÍÑ…ÑÕÌ€èôÈ¹MÑ…ÑÕÌ ¤(%É•ÑÕÉ¸•¹ÑÉ…°¹!•…ÉÑ‰•…ÑMÑ…ÑÕÍì($%•¹Ñ%è€€€€€ÍÑ…ÑÕÌ¹•¹Ñ%°($%Q•¹…¹Ñ%è€€€€ÍÑ…ÑÕÌ¹Q•¹…¹Ñ%°($%½µÁÕÑ•É9…µ”èÍÑ…ÑÕÌ¹!½ÍÑ¹…µ”°($%MÑ…ÑÕÌè€€€€€€ÍÑ…ÑÕÌ¹MÑ…ÑÕÌ°($%Ù•¹ÑÌè€€€€€€ÍÑ…ÑÕÌ¹Ù•¹ÑÌ°($%¥¹‘¥¹Ìè€€€€ÍÑ…ÑÕÌ¹¥¹‘¥¹Ì°($%ÉÉ½ÉÌè€€€€€€ÍÑ…ÑÕÌ¹ÉÉ½ÉÌ°($%EÕ•Õ••ÁÑ è€€È¹•¹ÑÉ…°¹EÕ•Õ••ÁÑ  ¤°(%ô)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤MÑ…ÑÕÌ ¤MÑ…ÑÕÌì(%Í½ÕÉ•½Õ¹Ğ€èô±•¸¡È¹Ñ…¥±•ÉÌ¤€¬±•¸¡È¹¹…Ñ¥Ù•M½ÕÉ•Ì¤(%¥˜È¹¥¹Ù•¹Ñ½Éå½±±•Ñ½È€„ô¹¥°ì($%Í½ÕÉ•½Õ¹Ğ¬¬(%ô(%¥˜È¹ÁÉ½•ÍÍÉ…Á €„ô¹¥°ì($%Í½ÕÉ•½Õ¹Ğ¬¬(%ô(%¥˜È¹ÁÉ½•ÍÍ9•Ñİ½É¬€„ô¹¥°ì($%Í½ÕÉ•½Õ¹Ğ¬¬(%ô(%¥˜È¹•‰Á™M•¹Í½È€„ô¹¥°ñğÈ¹•‰Á™!•±Á•È€„ô¹¥°ì($%Í½ÕÉ•½Õ¹Ğ¬¬(%ô(%¥˜È¹ÁÉ½Ñ•Ñ¥½¸€„ô¹¥°ì($%Í½ÕÉ•½Õ¹Ğ¬¬(%ô(%Ù…È±…ÍÑ%¹Ù•¹Ñ½ÉåĞ€©Ñ¥µ”¹Q¥µ”(%¥˜±…ÍÑ9…¹¼€èôÈ¹±…ÍÑ%¹Ù•¹Ñ½Éå9…¹¼¹1½… ¤ì±…ÍÑ9…¹¼€„ô€Àì($%Ù…±Õ”€èôÑ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¹UQ ¤($%±…ÍÑ%¹Ù•¹Ñ½ÉåĞ€ô€™Ù…±Õ”(%ô(%Ù…È±…ÍÑQÉ…¹ÍÁ½ÉÑMÕ•ÍÍĞ€©Ñ¥µ”¹Q¥µ”(%Ù…È±…ÍÑAÉ½•ÍÍÉ…Á¡Ğ€©Ñ¥µ”¹Q¥µ”(%Ù…È±…ÍÑAÉ½•ÍÍ9•Ñİ½É­Ğ€©Ñ¥µ”¹Q¥µ”(%¥˜±…ÍÑ9…¹¼€èôÈ¹±…ÍÑAÉ½•ÍÍÉ…Á¡9…¹¼¹1½… ¤ì±…ÍÑ9…¹¼€„ô€Àì($%Ù…±Õ”€èôÑ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¹UQ ¤($%±…ÍÑAÉ½•ÍÍÉ…Á¡Ğ€ô€™Ù…±Õ”(%ô(%¥˜±…ÍÑ9…¹¼€èôÈ¹±…ÍÑAÉ½•ÍÍ9•Ñİ½É­9…¹¼¹1½… ¤ì±…ÍÑ9…¹¼€„ô€Àì($%Ù…±Õ”€èôÑ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¹UQ ¤($%±…ÍÑAÉ½•ÍÍ9•Ñİ½É­Ğ€ô€™Ù…±Õ”(%ô(%¥˜±…ÍÑ9…¹¼€èôÈ¹±…ÍÑQÉ…¹ÍÁ½ÉÑMÕ•ÍÍ9…¹¼¹1½… ¤ì±…ÍÑ9…¹¼€„ô€Àì($%Ù…±Õ”€èôÑ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¹UQ ¤($%±…ÍÑQÉ…¹ÍÁ½ÉÑMÕ•ÍÍĞ€ô€™Ù…±Õ”(%ô(%Ù…È±…ÍÑ•ÉÑ¥™¥…Ñ•I•¹•İĞ€©Ñ¥µ”¹Q¥µ”(%¥˜±…ÍÑ9…¹¼€èôÈ¹±…ÍÑ•ÉÑ¥™¥…Ñ•I•¹•İ9…¹¼¹1½… ¤ì±…ÍÑ9…¹¼€„ô€Àì($%Ù…±Õ”€èôÑ¥µ”¹U¹¥à À°±…ÍÑ9…¹¼¤¹UQ ¤($%±…ÍÑ•ÉÑ¥™¥…Ñ•I•¹•İĞ€ô€™Ù…±Õ”(%ô(%Ù…È•ÉÑ¥™¥…Ñ•áÁ¥É•ÍĞ€©Ñ¥µ”¹Q¥µ”(%¥˜È¹™œ¹QÉ…¹ÍÁ½ÉĞ¹¹…‰±•ì($%¥˜•áÁ¥Éä°•ÉÈ€èô•¹É½±±µ•¹Ğ¹•ÉÑ¥™¥…Ñ•áÁ¥Éä¡È¹™œ¹QÉ…¹ÍÁ½ÉĞ¹•ÉÑ¥±”¤ì•ÉÈ€ôô¹¥°ì($$%Ù…±Õ”€èô•áÁ¥Éä¹UQ ¤($$%•ÉÑ¥™¥…Ñ•áÁ¥É•ÍĞ€ô€™Ù…±Õ”($%ô(%ô(%ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ€èôÑÉ…¹ÍÁ½ÉĞ¹=ÕÑ‰½áMÑ…ÑÍíô(%¥˜È¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à€„ô¹¥°ì($%¥˜ÍÑ…ÑÌ°•ÉÈ€èôÈ¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à¹MÑ…ÑÌ ¤ì•ÉÈ€ôô¹¥°ì($$%ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ€ôÍÑ…ÑÌ($%ô(%ô(%…Õ‘¥ÑMÑ…ÑÌ€èô¹…Ñ¥Ù”¹Õ‘¥ÑÍÍ•µ‰±åMÑ…ÑÍíô(%™½È|°Í½ÕÉ”€èôÉ…¹”È¹¹…Ñ¥Ù•M½ÕÉ•Ìì($%ÁÉ½Ù¥‘•È°½¬€èôÍ½ÕÉ”¸¡¥¹Ñ•É™…”ì($$%ÍÍ•µ‰±åMÑ…ÑÌ ¤¹…Ñ¥Ù”¹Õ‘¥ÑÍÍ•µ‰±åMÑ…ÑÌ($%ô¤($%¥˜€…½¬ì($$%½¹Ñ¥¹Õ”($%ô($%ÍÑ…ÑÌ€èôÁÉ½Ù¥‘•È¹ÍÍ•µ‰±åMÑ…ÑÌ ¤($%…Õ‘¥ÑMÑ…ÑÌ¹Ñ¥Ù•M•É¥…±Ì€¬ôÍÑ…ÑÌ¹Ñ¥Ù•M•É¥…±Ì($%…Õ‘¥ÑMÑ…ÑÌ¹ÍÍ•µ‰±•‘Ù•¹ÑÌ€¬ôÍÑ…ÑÌ¹ÍÍ•µ‰±•‘Ù•¹ÑÌ($%…Õ‘¥ÑMÑ…ÑÌ¹%¹½µÁ±•Ñ•ÍÍ•µ‰±¥•Ì€¬ôÍÑ…ÑÌ¹%¹½µÁ±•Ñ•ÍÍ•µ‰±¥•Ì($%…Õ‘¥ÑMÑ…ÑÌ¹É½ÁÁ•‘I•½É‘Ì€¬ôÍÑ…ÑÌ¹É½ÁÁ•‘I•½É‘Ì(%ô(%ÁÉ½•ÍÍÉ…Á¡MÑ…ÑÌ€èôÁÉ½•ÍÍÉ…Á ¹MÑ…ÑÍíô(%¥˜È¹ÁÉ½•ÍÍÉ…Á €„ô¹¥°ì($%ÁÉ½•ÍÍÉ…Á¡MÑ…ÑÌ€ôÈ¹ÁÉ½•ÍÍÉ…Á ¹MÑ…ÑÌ ¤(%ô(%ÁÉ½•ÍÍ9•Ñİ½É­MÑ…ÑÌ€èô¹•Ñİ½É­¥¹Ù•¹Ñ½Éä¹MÑ…ÑÍíô(%¥˜È¹ÁÉ½•ÍÍ9•Ñİ½É¬€„ô¹¥°ì($%ÁÉ½•ÍÍ9•Ñİ½É­MÑ…ÑÌ€ôÈ¹ÁÉ½•ÍÍ9•Ñİ½É¬¹MÑ…ÑÌ ¤(%ô(%•‰Á™!•…±Ñ €èô•‰Á™Í•¹Í½È¹!•…±Ñ¡íô(%•‰Á™!•±Á•ÉEÕ•Õ•1½ÍÌ€èôÕ¥¹ĞØĞ À¤(%¥˜È¹•‰Á™M•¹Í½È€„ô¹¥°ì($%•‰Á™!•…±Ñ €ôÈ¹•‰Á™M•¹Í½È¹!•…±Ñ  ¤(%ô•±Í”¥˜È¹•‰Á™!•±Á•È€„ô¹¥°ì($%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹I1½¬ ¤($%•‰Á™!•…±Ñ €ôÈ¹•‰Á™!•±Á•É!•…±Ñ ¹M•¹Í½È($%•‰Á™!•±Á•ÉEÕ•Õ•1½ÍÌ€ôÈ¹•‰Á™!•±Á•É!•…±Ñ ¹EÕ•Õ•É½ÁÁ•($%È¹•‰Á™!•±Á•É!•…±Ñ¡5Ô¹IU¹±½¬ ¤(%ô•±Í”¥˜È¹•‰Á™…±±‰…­I•…Í½¸€„ô€ˆˆì($%•‰Á™!•…±Ñ ¹…±±‰…­I•…Í½¸€ôÈ¹•‰Á™…±±‰…­I•…Í½¸(%ô(%Ù…È•‰Á™1…ÍÑÙ•¹ÑĞ€©Ñ¥µ”¹Q¥µ”(%¥˜€…•‰Á™!•…±Ñ ¹1…ÍÑÙ•¹ÑĞ¹%Íi•É¼ ¤ì($%Ù…±Õ”€èô•‰Á™!•…±Ñ ¹1…ÍÑÙ•¹ÑĞ¹UQ ¤($%•‰Á™1…ÍÑÙ•¹ÑĞ€ô€™Ù…±Õ”(%ô(%ÍÑ…ÑÕÌ€èôMÑ…ÑÕÍì($%MÑ…ÑÕÌè€€€€€€€€€€€€€€€€€€€‰ÉÕ¹¹¥¹œˆ°($%•¹Ñ%è€€€€€€€€€€€€€€€€€È¹™œ¹•¹Ñ%°($%Q•¹…¹Ñ%è€€€€€€€€€€€€€€€€È¹™œ¹Q•¹…¹Ñ%°($%!½ÍÑ¹…µ”è€€€€€€€€€€€€€€€€È¹¡½ÍÑ¹…µ”°($%MÑ…ÉÑ•‘Ğè€€€€€€€€€€€€€€€È¹ÍÑ…ÉÑ•‘Ğ°($%UÁÑ¥µ”è€€€€€€€€€€€€€€€€€€Ñ¥µ”¹M¥¹”¡È¹ÍÑ…ÉÑ•‘Ğ¤¹I½Õ¹¡Ñ¥µ”¹M•½¹¤¹MÑÉ¥¹œ ¤°($%Ù•¹ÑÌè€€€€€€€€€€€€€€€€€€È¹•Ù•¹Ñ½Õ¹Ğ¹1½… ¤°($%¥¹‘¥¹Ìè€€€€€€€€€€€€€€€€È¹™¥¹‘¥¹½Õ¹Ğ¹1½… ¤°($%ÉÉ½ÉÌè€€€€€€€€€€€€€€€€€€È¹•ÉÉ½É½Õ¹Ğ¹1½… ¤°($%M½ÕÉ•Ìè€€€€€€€€€€€€€€€€€Í½ÕÉ•½Õ¹Ğ°($%¥±•M½ÕÉ•Ìè€€€€€€€€€€€€€±•¸¡È¹Ñ…¥±•ÉÌ¤°($%9…Ñ¥Ù•M½ÕÉ•Ìè€€€€€€€€€€€±•¸¡È¹¹…Ñ¥Ù•M½ÕÉ•Ì¤°($%9…Ñ¥Ù•Ù•¹ÑÌè€€€€€€€€€€€€È¹¹…Ñ¥Ù•Ù•¹Ñ½Õ¹Ğ¹1½… ¤°($%Õ‘¥ÑÑ¥Ù•M•É¥…±Ìè€€€€€€…Õ‘¥ÑMÑ…ÑÌ¹Ñ¥Ù•M•É¥…±Ì°($%Õ‘¥ÑÍÍ•µ‰±•‘Ù•¹ÑÌè€€€€…Õ‘¥ÑMÑ…ÑÌ¹ÍÍ•µ‰±•‘Ù•¹ÑÌ°($%Õ‘¥Ñ%¹½µÁ±•Ñ•É½ÕÁÌè€€€…Õ‘¥ÑMÑ…ÑÌ¹%¹½µÁ±•Ñ•ÍÍ•µ‰±¥•Ì°($%Õ‘¥ÑÉ½ÁÁ•‘I•½É‘Ìè€€€€€…Õ‘¥ÑMÑ…ÑÌ¹É½ÁÁ•‘I•½É‘Ì°($%%¹…‰±•è€€€€€€€€€€€€€€€È¹™œ¹$¹¹…‰±•°($%$è€€€€€€€€€€€€€€€€€€€€€€È¹%MÑ…ÑÕÌ ¤°($%%¹Ù•¹Ñ½Éå¹…‰±•è€€€€€€€€È¹¥¹Ù•¹Ñ½Éå½±±•Ñ½È€„ô¹¥°°($%%¹Ù•¹Ñ½ÉåIÕ¹Ìè€€€€€€€€€€€È¹¥¹Ù•¹Ñ½Éå½Õ¹Ğ¹1½… ¤°($%AÉ½•ÍÍÉ…Á¡¹…‰±•è€€€€€È¹ÁÉ½•ÍÍÉ…Á €„ô¹¥°°($%AÉ½•ÍÍÉ…Á¡Ù•¹ÑÌè€€€€€€È¹ÁÉ½•ÍÍÉ…Á¡Ù•¹Ñ½Õ¹Ğ¹1½… ¤°($%AÉ½•ÍÍÉ…Á¡Ñ¥Ù”è€€€€€€ÁÉ½•ÍÍÉ…Á¡MÑ…ÑÌ¹Ñ¥Ù•AÉ½•ÍÍ•Ì°($%AÉ½•ÍÍÉ…Á¡á¥Ñ•è€€€€€€ÁÉ½•ÍÍÉ…Á¡MÑ…ÑÌ¹á¥Ñ•‘AÉ½•ÍÍ•Ì°($%AÉ½•ÍÍÉ…Á¡I•½¹¥±•Ìè€€ÁÉ½•ÍÍÉ…Á¡MÑ…ÑÌ¹I•½¹¥±¥…Ñ¥½¹Ì°($%1…ÍÑAÉ½•ÍÍÉ…Á¡Ğè€€€€€€±…ÍÑAÉ½•ÍÍÉ…Á¡Ğ°($%AÉ½•ÍÍ9•Ñİ½É­¹…‰±•è€€€È¹ÁÉ½•ÍÍ9•Ñİ½É¬€„ô¹¥°°($%AÉ½•ÍÍ9•Ñİ½É­Ù•¹ÑÌè€€€€È¹ÁÉ½•ÍÍ9•Ñİ½É­Ù•¹Ñ½Õ¹Ğ¹1½… ¤°($%AÉ½•ÍÍ9•Ñİ½É­M½­•ÑÌè€€€ÁÉ½•ÍÍ9•Ñİ½É­MÑ…ÑÌ¹-¹½İ¹M½­•ÑÌ°($%AÉ½•ÍÍ9•Ñİ½É­M…¹Ìè€€€€€ÁÉ½•ÍÍ9•Ñİ½É­MÑ…ÑÌ¹M…¹Ì°($%AÉ½•ÍÍ9•Ñİ½É­]…É¹¥¹Ìè€€ÁÉ½•ÍÍ9•Ñİ½É­MÑ…ÑÌ¹]…É¹¥¹Ì°($%1…ÍÑAÉ½•ÍÍ9•Ñİ½É­Ğè€€€€±…ÍÑAÉ½•ÍÍ9•Ñİ½É­Ğ°($%	AM•¹Í½É¹…‰±•è€€€€€€€•‰Á™!•…±Ñ ¹¹…‰±•°($%	AÙ•¹ÑÌè€€€€€€€€€€€€€€È¹•‰Á™Ù•¹Ñ½Õ¹Ğ¹1½… ¤°($%	A1½…‘•‘AÉ½É…µÌè€€€€€€•‰Á™!•…±Ñ ¹1½…‘•‘AÉ½É…µÌ°($%	AÑÑ…¡•‘!½½­Ìè€€€€€€€•‰Á™!•…±Ñ ¹ÑÑ…¡•‘!½½­Ì°($%	AI¥¹	Õ™™•É1½ÍÌè€€€€€€•‰Á™!•…±Ñ ¹I¥¹	Õ™™•É1½ÍÌ°($%	AA…ÉÍ•ÉÉ½ÉÌè€€€€€€€€€•‰Á™!•…±Ñ ¹A…ÉÍ•ÉÉ½ÉÌ°($%	AÙ•¹ÑÍA•ÉM•½¹è€€€€€•‰Á™!•…±Ñ ¹Ù•¹ÑÍA•ÉM•½¹°($%	AQ¡É½ÑÑ±•‘Ù•¹ÑÌè€€€€€•‰Á™!•…±Ñ ¹Q¡É½ÑÑ±•‘Ù•¹ÑÌ°($%	A1…ÍÑÙ•¹ÑĞè€€€€€€€€€•‰Á™1…ÍÑÙ•¹ÑĞ°($%	A…±±‰…­I•…Í½¸è€€€€€€•‰Á™!•…±Ñ ¹…±±‰…­I•…Í½¸°($%	A!•±Á•ÉEÕ•Õ•1½ÍÌè€€€€€•‰Á™!•±Á•ÉEÕ•Õ•1½ÍÌ°($%1…ÍÑ%¹Ù•¹Ñ½ÉåĞè€€€€€€€€€±…ÍÑ%¹Ù•¹Ñ½ÉåĞ°($%%¹Ù•¹Ñ½Éå%¹Ñ•ÉÙ…°è€€€€€€€È¹™œ¹%¹Ù•¹Ñ½Éä¹%¹Ñ•ÉÙ…°°($%QÉ…¹ÍÁ½ÉÑ¹…‰±•è€€€€€€€€È¹ÑÉ…¹ÍÁ½ÉÑM•¹‘•È€„ô¹¥°°($%QÉ…¹ÍÁ½ÉÑA•¹‘¥¹œè€€€€€€€€ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ¹A•¹‘¥¹œ°($%QÉ…¹ÍÁ½ÉÑA•¹‘¥¹	åÑ•Ìè€€€ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ¹A•¹‘¥¹	åÑ•Ì°($%QÉ…¹ÍÁ½ÉÑ•…‘1•ÑÑ•Èè€€€€€ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ¹•…‘1•ÑÑ•È°($%QÉ…¹ÍÁ½ÉÑ•…‘1•ÑÑ•É	åÑ•ÌèÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ¹•…‘1•ÑÑ•É	Ñä°($%QÉ…¹ÍÁ½ÉÑM•¹Ğè€€€€€€€€€€€È¹ÑÉ…¹ÍÁ½ÉÑM•¹Ñ½Õ¹Ğ¹1½… ¤°($%QÉ…¹ÍÁ½ÉÑÉÉ½ÉÌè€€€€€€€€€È¹ÑÉ…¹ÍÁ½ÉÑÉÉ½É½Õ¹Ğ¹1½… ¤°($%QÉ…¹ÍÁ½ÉÑ	…­ÁÉ•ÍÍÕÉ”è€€€È¹ÑÉ…¹ÍÁ½ÉÑ=ÕÑ‰½à€„ô¹¥°€˜˜ÑÉ…¹ÍÁ½ÉÑMÑ…ÑÌ¹A•¹‘¥¹œ€øôÈ¹™œ¹QÉ…¹ÍÁ½ÉĞ¹A•¹‘¥¹]…É¸°($%1…ÍÑQÉ…¹ÍÁ½ÉÑMÕ•ÍÍĞè€€±…ÍÑQÉ…¹ÍÁ½ÉÑMÕ•ÍÍĞ°($%•ÉÑ¥™¥…Ñ•ÕÑ½I•¹•Üè€€€€È¹™œ¹QÉ…¹ÍÁ½ÉĞ¹¹…‰±•€˜˜È¹™œ¹QÉ…¹ÍÁ½ÉĞ¹ÕÑ½I•¹•Ü°($%•ÉÑ¥™¥…Ñ•áÁ¥É•ÍĞè€€€€•ÉÑ¥™¥…Ñ•áÁ¥É•ÍĞ°($%•ÉÑ¥™¥…Ñ•I•¹•İ…±Ìè€€€€€È¹•ÉÑ¥™¥…Ñ•I•¹•İ…±½Õ¹Ğ¹1½… ¤°($%1…ÍÑ•ÉÑ¥™¥…Ñ•I•¹•İĞè€€±…ÍÑ•ÉÑ¥™¥…Ñ•I•¹•İĞ°($%	Õ¥±è€€€€€€€€€€€€€€€€€€€‰Õ¥±‘¥¹™¼¹ÕÉÉ•¹Ğ ¤°($%M…™•Ñå5½‘•°è€€€€€€€€€€€€€€‰$µ…ä…¹…±åé”•Ù¥‘•¹”ì½¹±äÑåÁ•Ñ½½±Ì‰•¡¥¹‘•Ñ•Éµ¥¹¥ÍÑ¥ŒÁ½±¥äµ…ä…Ğˆ°(%ô(%¥˜È¹ÁÉ½Ñ•Ñ¥½¸€„ô¹¥°ì($%ÁÉ½Ñ•Ñ¥½¹MÑ…ÑÕÌ€èôÈ¹ÁÉ½Ñ•Ñ¥½¸¹MÑ…ÑÕÌ ¤($%ÍÑ…ÑÕÌ¹AÉ½Ñ•Ñ¥½¸€ô€™ÁÉ½Ñ•Ñ¥½¹MÑ…ÑÕÌ(%ô(%É•ÑÕÉ¸ÍÑ…ÑÕÌ)ô()™Õ¹Œ€¡È€©IÕ¹Ñ¥µ”¤±½Í” ¤•ÉÉ½Èì(%É•ÑÕÉ¸È¹©½ÕÉ¹…°¹±½Í” ¤)ô