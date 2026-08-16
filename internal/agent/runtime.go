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
				runtime.ebpfFallbackReason = err.Error()
				logger.Printf("Linux eBPF sensor unavailable: %v; auditd/journald fallback continues", err)
			} else {
				runtime.ebpfSensor = sensor
			}
		}
	}
	if cfg.Transport.Enabled {
		outbox, err := transport.OpenOutbox(cfg.DataDir)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry outbox: %w", err)
		}
		timeout, err := time.ParseDuration(cfg.Transport.Timeout)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry timeout: %w", err)
		}
		flushInterval, err := time.ParseDuration(cfg.Transport.FlushInterval)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry flush interval: %w", err)
		}
		renewBefore := time.Duration(0)
		renewCheckInterval := time.Duration(0)
		if cfg.Transport.AutoRenew {
			renewBefore, err = time.ParseDuration(cfg.Transport.RenewBefore)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize certificate renew-before interval: %w", err)
			}
			renewCheckInterval, err = time.ParseDuration(cfg.Transport.RenewCheckInterval)
			if err != nil {
				_ = journal.Close()
				return nil, fmt.Errorf("initialize certificate renewal check interval: %w", err)
			}
		}
		sender, err := transport.NewSender(outbox, transport.SenderOptions{
			Endpoint:           cfg.Transport.Endpoint,
			AgentID:            cfg.AgentID,
			TenantID:           cfg.TenantID,
			CertFile:           cfg.Transport.CertFile,
			KeyFile:            cfg.Transport.KeyFile,
			CAFile:             cfg.Transport.CAFile,
			ServerName:         cfg.Transport.ServerName,
			Timeout:            timeout,
			AutoRenew:          cfg.Transport.AutoRenew,
			RenewalEndpoint:    cfg.Transport.RenewalEndpoint,
			RenewBefore:        renewBefore,
			RenewCheckInterval: renewCheckInterval,
		})
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize telemetry sender: %w", err)
		}
		runtime.transportOutbox = outbox
		runtime.transportSender = sender
		runtime.transportFlushInterval = flushInterval
	}
	if cfg.Central.Enabled {
		client, err := central.New(cfg.Central, cfg.AgentID, cfg.TenantID, hostname, logger)
		if err != nil {
			_ = journal.Close()
			return nil, fmt.Errorf("initialize Central transport: %w", err)
		}
		runtime.central = client
	}
	protectionController, err := protection.NewController(cfg, logger)
	if err != nil {
		_ = journal.Close()
		return nil, fmt.Errorf("initialize Windows protection: %w", err)
	}
	runtime.protection = protectionController
	return runtime, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r.ebpfSensor != nil {
		defer func() { _ = r.ebpfSensor.Close() }()
	}
	startup := map[string]interface{}{
		"agent_id":                r.cfg.AgentID,
		"tenant_id":               r.cfg.TenantID,
		"hostname":                r.hostname,
		"file_sources":            len(r.tailers),
		"native_sources":          len(r.nativeSources),
		"inventory_enabled":       r.inventoryCollector != nil,
		"signed_baseline_enabled": r.baselineStore != nil,
		"inventory_interval":      r.cfg.Inventory.Interval,
		"process_graph_enabled":   r.processGraph != nil,
		"process_network_enabled": r.processNetwork != nil,
		"ebpf_sensor_configured":  r.ebpfSensor != nil || r.ebpfHelper != nil,
		"transport_enabled":       r.transportSender != nil,
		"central_enabled":         r.central != nil,
		"certificate_auto_renew":  r.cfg.Transport.AutoRenew,
		"build":                   buildinfo.Current(),
		"ai_enabled":              r.cfg.AI.Enabled,
		"ai_auto_analyze":         r.aiQueue != nil,
		"protection_enabled":      r.protection != nil,
		"safety_model":            "untrusted evidence -> deterministic policy gate -> typed tools",
	}
	if _, err := r.journal.Append("agent.start", startup); err != nil {
		return err
	}
	r.logger.Printf("agent started id=%s file_sources=%d native_sources=%d inventory_enabled=%t transport_enabled=%t central_enabled=%t ai_enabled=%t", r.cfg.AgentID, len(r.tailers), len(r.nativeSources), r.inventoryCollector != nil, r.transportSender != nil, r.central != nil, r.cfg.AI.Enabled)

	errCh := make(chan error, 1)
	if r.cfg.API.Enabled {
		token, err := api.EnsureToken(r.cfg.API.TokenFile)
		if err != nil {
			return err
		}
		server := api.New(r.cfg.API.Listen, token, func() interface{} { return r.Status() }, r.Ingest)
		if r.aiClient != nil {
			if err := server.AddReadOnly("/v1/ai", func() interface{} { return r.AIStatus() }); err != nil {
				return err
			}
		}
		if r.protection != nil {
			if err := server.AddReadOnly("/v1/protection", func() interface{} { return r.protection.Status() }); err != nil {
				return err
			}
			if err := server.AddCommand("/v1/protection/scan", func(_ context.Context, body json.RawMessage) (interface{}, error) {
				var request struct {
					Profile string `json:"profile"`
				}
				decoder := json.NewDecoder(bytes.NewReader(body))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&request); err != nil {
					return nil, fmt.Errorf("invalid scan request: %w", err)
				}
				if request.Profile == "" {
					request.Profile = "quick"
				}
				id, err := r.protection.StartScan(ctx, request.Profile, func(outcome protection.Outcome) {
					if recordErr := r.recordProtectionOutcome(outcome); recordErr != nil {
						r.recordCollectorError("windows-protection", recordErr)
					}
				})
				if err != nil {
					return nil, err
				}
				return map[string]interface{}{"status": "accepted", "scan_id": id, "profile": request.Profile}, nil
			}); err != nil {
				return err
			}
		}
		go func() { errCh <- server.Run(ctx) }()
		r.logger.Printf("local API listening on %s; only typed protection controls are exposed", r.cfg.API.Listen)
	}
	if r.transportSender != nil {
		go r.runTransport(ctx)
	}
	if r.central != nil {
		go func() {
			if err := r.central.Run(ctx, r.centralStatus); err != nil {
				r.logger.Printf("Central transport stopped: %v", err)
			}
		}()
		r.logger.Printf("Central transport enabled url=%s", r.cfg.Central.URL)
	}
	if r.aiQueue != nil {
		go r.runAI(ctx)
		r.logger.Printf("llm operation=worker status=started model=%s minimum_severity=%s queue_size=%d min_interval=%s audit_log=%s", r.cfg.AI.Model, r.cfg.AI.MinimumSeverity, cap(r.aiQueue), r.cfg.AI.MinInterval, r.cfg.AI.AuditLogFile)
	}
	if r.protection != nil {
		go r.protection.Run(ctx, func(outcome protection.Outcome) {
			if err := r.recordProtectionOutcome(outcome); err != nil {
				r.recordCollectorError("windows-protection", err)
			}
		})
	}

	r.collectProcessGraph(ctx, true)
	r.collectProcessNetwork(ctx, true)
	r.startEBPFSensor(ctx)
	r.collectInventory(ctx, true)
	r.poll(ctx)
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_, _ = r.journal.Append("agent.stop", map[string]interface{}{"reason": ctx.Err().Error(), "status": r.Status()})
			return nil
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("local API: %w", err)
			}
		case <-ticker.C:
			r.poll(ctx)
			r.collectProcessGraph(ctx, false)
			r.collectProcessNetwork(ctx, false)
			r.collectInventory(ctx, false)
		}
	}
}

func (r *Runtime) runTransport(ctx context.Context) {
	delay := time.Duration(0)
	lastError := ""
	backpressureLogged := false
	for {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else if ctx.Err() != nil {
			return
		}

		result, err := r.transportSender.Flush(ctx, r.cfg.Transport.BatchSize)
		r.transportSentCount.Add(uint64(result.Sent))
		r.transportDeadLetterCount.Add(uint64(result.DeadLetter))
		if result.CertificateRenewed {
			r.certificateRenewalCount.Add(1)
			r.lastCertificateRenewNano.Store(time.Now().UTC().UnixNano())
			r.logger.Printf("Agent client certificate renewed expires_at=%v", result.CertificateExpiresAt)
			_, _ = r.journal.Append("identity.certificate_renewed", map[string]interface{}{
				"expires_at": result.CertificateExpiresAt,
			})
		}
		if result.Sent > 0 {
			r.lastTransportSuccessNano.Store(time.Now().UTC().UnixNano())
		}
		if result.DeadLetter > 0 {
			_, _ = r.journal.Append("transport.dead_letter", map[string]interface{}{
				"count": result.DeadLetter,
			})
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			r.transportErrorCount.Add(1)
			r.errorCount.Add(1)
			message := err.Error()
			if message != lastError {
				r.logger.Printf("telemetry transport error: %v", err)
				_, _ = r.journal.Append("transport.error", map[string]string{"error": message})
				lastError = message
			}
			if delay <= 0 {
				delay = r.transportFlushInterval
			}
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		} else {
			if lastError != "" {
				r.logger.Printf("telemetry transport recovered")
				_, _ = r.journal.Append("transport.recovered", map[string]interface{}{"sent": result.Sent})
				lastError = ""
			}
			delay = r.transportFlushInterval
		}

		if stats, statsErr := r.transportOutbox.Stats(); statsErr == nil {
			backpressure := stats.Pending >= r.cfg.Transport.PendingWarn
			if backpressure && !backpressureLogged {
				r.logger.Printf("telemetry outbox backpressure pending=%d bytes=%d", stats.Pending, stats.PendingBytes)
				_, _ = r.journal.Append("transport.backpressure", map[string]interface{}{
					"pending": stats.Pending,
					"bytes":   stats.PendingBytes,
				})
			}
			if !backpressure && backpressureLogged {
				_, _ = r.journal.Append("transport.backpressure_cleared", map[string]interface{}{
					"pending": stats.Pending,
				})
			}
			backpressureLogged = backpressure
		}
	}
}

func (r *Runtime) poll(ctx context.Context) {
	r.pollFiles(ctx)
	r.pollNative(ctx)
}

func (r *Runtime) pollFiles(ctx context.Context) {
	for _, tailer := range r.tailers {
		if err := ctx.Err(); err != nil {
			return
		}
		events, errs := tailer.Poll()
		for _, err := range errs {
			r.recordCollectorError("file-tail", err)
		}
		for _, event := range events {
			if _, err := r.process(event); err != nil {
				r.errorCount.Add(1)
				r.logger.Printf("event processing error: %v", err)
			}
		}
	}
}

func (r *Runtime) pollNative(ctx context.Context) {
	for _, source := range r.nativeSources {
		if err := ctx.Err(); err != nil {
			return
		}
		batch, errs := source.Poll(ctx)
		for _, err := range errs {
			r.recordCollectorError(source.Kind()+"/"+source.ID(), err)
		}
		processed := true
		for _, event := range batch.Events {
			if _, err := r.process(event); err != nil {
				processed = false
				r.recordCollectorError(source.Kind()+"/"+source.ID(), err)
				break
			}
			r.nativeEventCount.Add(1)
		}
		if processed {
			if err := batch.Acknowledge(); err != nil {
				r.recordCollectorError(source.Kind()+"/"+source.ID()+"/cursor", err)
			}
		}
	}
}

func (r *Runtime) collectInventory(ctx context.Context, force bool) {
	if r.inventoryCollector == nil || ctx.Err() != nil {
		return
	}
	lastNano := r.lastInventoryNano.Load()
	if !force && lastNano != 0 && time.Since(time.Unix(0, lastNano)) < r.inventoryInterval {
		return
	}
	event, err := r.inventoryCollector.Event(ctx)
	if err != nil {
		r.recordCollectorError("native-inventory", err)
		return
	}
	redact.Event(&event)
	if _, err := r.process(event); err != nil {
		r.recordCollectorError("native-inventory", err)
		return
	}
	if r.baselineStore != nil {
		snapshot, err := baseline.SnapshotFromEvent(event)
		if err != nil {
			r.recordCollectorError("inventory-baseline", err)
			return
		}
		if err := r.baselineStore.Save(snapshot); err != nil {
			r.recordCollectorError("inventory-baseline", err)
			return
		}
	}
	collectedAt := time.Now().UTC()
	r.lastInventoryNano.Store(collectedAt.UnixNano())
	r.inventoryCount.Add(1)
	r.logger.Printf("asset inventory collected processes=%t services=%t listeners=%t software=%t", r.cfg.Inventory.IncludeProcesses, r.cfg.Inventory.IncludeServices, r.cfg.Inventory.IncludeListeners, r.cfg.Inventory.IncludeSoftware)
}

func (r *Runtime) collectProcessGraph(ctx context.Context, force bool) {
	if r.processGraph == nil || ctx.Err() != nil {
		return
	}
	lastNano := r.lastProcessGraphNano.Load()
	if !force && lastNano != 0 && time.Since(time.Unix(0, lastNano)) < r.processGraphInterval {
		return
	}
	batch, err := r.processGraph.Reconcile(ctx)
	if err != nil {
		r.recordCollectorError("linux-process-graph", err)
		return
	}
	for _, event := range batch.Events {
		if _, err := r.process(event); err != nil {
			r.recordCollectorError("linux-process-graph", err)
			return
		}
		r.processGraphEventCount.Add(1)
	}
	if err := batch.Acknowledge(); err != nil {
		r.recordCollectorError("linux-process-graph/checkpoint", err)
		return
	}
	r.lastProcessGraphNano.Store(time.Now().UTC().UnixNano())
}

func (r *Runtime) collectProcessNetwork(ctx context.Context, force bool) {
	if r.processNetwork == nil || ctx.Err() != nil {
		return
	}
	lastNano := r.lastProcessNetworkNano.Load()
	if !force && lastNano != 0 && time.Since(time.Unix(0, lastNano)) < r.processNetworkInterval {
		return
	}
	batch, err := r.processNetwork.Reconcile(ctx)
	if err != nil {
		r.recordCollectorError("linux-process-network", err)
		return
	}
	for _, event := range batch.Events {
		if _, err := r.process(event); err != nil {
			r.recordCollectorError("linux-process-network", err)
			return
		}
		r.processNetworkEventCount.Add(1)
	}
	if err := batch.Acknowledge(); err != nil {
		r.recordCollectorError("linux-process-network/checkpoint", err)
		return
	}
	r.lastProcessNetworkNano.Store(time.Now().UTC().UnixNano())
}

func (r *Runtime) startEBPFSensor(ctx context.Context) {
	if r.ebpfHelper != nil {
		go r.runSensorHelper(ctx)
		return
	}
	if r.ebpfSensor == nil {
		return
	}
	if err := r.ebpfSensor.Start(ctx, func(event model.Event) error {
		if _, err := r.process(event); err != nil {
			return err
		}
		r.ebpfEventCount.Add(1)
		return nil
	}); err != nil {
		r.logger.Printf("Linux eBPF sensor unavailable: %v; auditd/journald fallback continues", err)
	}
}

func (r *Runtime) runSensorHelper(ctx context.Context) {
	lastError := ""
	for ctx.Err() == nil {
		err := r.ebpfHelper.Run(ctx, func(event model.Event) error {
			if _, err := r.process(event); err != nil {
				return err
			}
			r.ebpfEventCount.Add(1)
			return nil
		}, func(health sensoripc.Health) {
			r.ebpfHelperHealthMu.Lock()
			r.ebpfHelperHealth = health
			r.ebpfHelperHealthMu.Unlock()
		})
		if ctx.Err() != nil {
			return
		}
		message := "sensor helper stopped"
		if err != nil {
			message = err.Error()
		}
		if message != lastError {
			r.logger.Printf("Linux sensor helper unavailable: %v; auditd/journald fallback continues", err)
			lastError = message
		}
		r.ebpfHelperHealthMu.Lock()
		r.ebpfHelperHealth.Sensor.Enabled = false
		r.ebpfHelperHealth.Sensor.FallbackReason = message
		r.ebpfHelperHealthMu.Unlock()
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (r *Runtime) recordCollectorError(collector string, err error) {
	if err == nil {
		return
	}
	r.errorCount.Add(1)
	r.logger.Printf("collector error collector=%s error=%v", collector, err)
	_, _ = r.journal.Append("collector.error", map[string]string{"collector": collector, "error": err.Error()})
}

func (r *Runtime) Ingest(_ context.Context, event model.Event) ([]model.Finding, error) {
	return r.process(event)
}

func (r *Runtime) process(event model.Event) ([]model.Finding, error) {
	if r.processGraph != nil {
		r.processGraph.Enrich(&event)
	}
	event.Prepare()
	event.AgentID = r.cfg.AgentID
	event.TenantID = r.cfg.TenantID
	if event.Asset.Hostname == "" {
		event.Asset.Hostname = r.hostname
	}
	redact.Event(&event)
	if _, err := r.journal.Append("event", event); err != nil {
		return nil, err
	}
	r.eventCount.Add(1)
	findings := r.detector.Inspect(event)
	for _, finding := range findings {
		if _, err := r.journal.Append("finding", finding); err != nil {
			return findings, err
		}
		r.findingCount.Add(1)
		encoded, _ := json.Marshal(finding)
		r.logger.Printf("finding %s", encoded)
	}
	if r.transportOutbox != nil {
		if err := r.transportOutbox.Enqueue(event); err != nil {
			return findings, fmt.Errorf("queue telemetry for Control Plane: %w", err)
		}
	}
	if r.central != nil {
		r.central.Enqueue(event, findings)
	}
	r.enqueueAI(event, findings)
	if r.protection != nil {
		outcome, report, err := r.protection.InspectEvent(context.Background(), event)
		if err != nil {
			r.recordCollectorError("windows-protection/process", err)
		} else if report {
			if err := r.recordProtectionOutcome(outcome); err != nil {
				return findings, err
			}
			if outcome.Finding != nil {
				findings = append(findings, *outcome.Finding)
			}
		}
	}
	return findings, nil
}

func (r *Runtime) recordProtectionOutcome(outcome protection.Outcome) error {
	if outcome.Event == nil {
		return nil
	}
	event := *outcome.Event
	event.AgentID = r.cfg.AgentID
	event.TenantID = r.cfg.TenantID
	if event.Asset.Hostname == "" {
		event.Asset.Hostname = r.hostname
	}
	event.Prepare()
	redact.Event(&event)
	if _, err := r.journal.Append("event", event); err != nil {
		return err
	}
	r.eventCount.Add(1)
	findings := []model.Finding{}
	if outcome.Finding != nil {
		finding := *outcome.Finding
		finding.AgentID = r.cfg.AgentID
		finding.TenantID = r.cfg.TenantID
		finding.Asset = event.Asset
		finding.EvidenceEventIDs = []string{event.ID}
		if finding.Attributes == nil {
			finding.Attributes = map[string]interface{}{}
		}
		finding.Attributes["actions"] = outcome.Actions
		if _, err := r.journal.Append("finding", finding); err != nil {
			return err
		}
		r.findingCount.Add(1)
		findings = append(findings, finding)
	}
	if r.transportOutbox != nil {
		if err := r.transportOutbox.Enqueue(event); err != nil {
			return err
		}
	}
	if r.central != nil {
		r.central.Enqueue(event, findings)
	}
	return nil
}

func (r *Runtime) centralStatus() central.HeartbeatStatus {
	status := r.Status()
	return central.HeartbeatStatus{
		AgentID:      status.AgentID,
		TenantID:     status.TenantID,
		ComputerName: status.Hostname,
		Status:       status.Status,
		Events:       status.Events,
		Findings:     status.Findings,
		Errors:       status.Errors,
		QueueDepth:   r.central.QueueDepth(),
	}
}

func (r *Runtime) Status() Status {
	sourceCount := len(r.tailers) + len(r.nativeSources)
	if r.inventoryCollector != nil {
		sourceCount++
	}
	if r.processGraph != nil {
		sourceCount++
	}
	if r.processNetwork != nil {
		sourceCount++
	}
	if r.ebpfSensor != nil || r.ebpfHelper != nil {
		sourceCount++
	}
	if r.protection != nil {
		sourceCount++
	}
	var lastInventoryAt *time.Time
	if lastNano := r.lastInventoryNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastInventoryAt = &value
	}
	var lastTransportSuccessAt *time.Time
	var lastProcessGraphAt *time.Time
	var lastProcessNetworkAt *time.Time
	if lastNano := r.lastProcessGraphNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastProcessGraphAt = &value
	}
	if lastNano := r.lastProcessNetworkNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastProcessNetworkAt = &value
	}
	if lastNano := r.lastTransportSuccessNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastTransportSuccessAt = &value
	}
	var lastCertificateRenewAt *time.Time
	if lastNano := r.lastCertificateRenewNano.Load(); lastNano != 0 {
		value := time.Unix(0, lastNano).UTC()
		lastCertificateRenewAt = &value
	}
	var certificateExpiresAt *time.Time
	if r.cfg.Transport.Enabled {
		if expiry, err := enrollment.CertificateExpiry(r.cfg.Transport.CertFile); err == nil {
			value := expiry.UTC()
			certificateExpiresAt = &value
		}
	}
	transportStats := transport.OutboxStats{}
	if r.transportOutbox != nil {
		if stats, err := r.transportOutbox.Stats(); err == nil {
			transportStats = stats
		}
	}
	auditStats := native.AuditAssemblyStats{}
	for _, source := range r.nativeSources {
		provider, ok := source.(interface {
			AssemblyStats() native.AuditAssemblyStats
		})
		if !ok {
			continue
		}
		stats := provider.AssemblyStats()
		auditStats.ActiveSerials += stats.ActiveSerials
		auditStats.AssembledEvents += stats.AssembledEvents
		auditStats.IncompleteAssemblies += stats.IncompleteAssemblies
		auditStats.DroppedRecords += stats.DroppedRecords
	}
	processGraphStats := processgraph.Stats{}
	if r.processGraph != nil {
		processGraphStats = r.processGraph.Stats()
	}
	processNetworkStats := networkinventory.Stats{}
	if r.processNetwork != nil {
		processNetworkStats = r.processNetwork.Stats()
	}
	ebpfHealth := ebpfsensor.Health{}
	ebpfHelperQueueLoss := uint64(0)
	if r.ebpfSensor != nil {
		ebpfHealth = r.ebpfSensor.Health()
	} else if r.ebpfHelper != nil {
		r.ebpfHelperHealthMu.RLock()
		ebpfHealth = r.ebpfHelperHealth.Sensor
		ebpfHelperQueueLoss = r.ebpfHelperHealth.QueueDropped
		r.ebpfHelperHealthMu.RUnlock()
	} else if r.ebpfFallbackReason != "" {
		ebpfHealth.FallbackReason = r.ebpfFallbackReason
	}
	var ebpfLastEventAt *time.Time
	if !ebpfHealth.LastEventAt.IsZero() {
		value := ebpfHealth.LastEventAt.UTC()
		ebpfLastEventAt = &value
	}
	status := Status{
		Status:                   "running",
		AgentID:                  r.cfg.AgentID,
		TenantID:                 r.cfg.TenantID,
		Hostname:                 r.hostname,
		StartedAt:                r.startedAt,
		Uptime:                   time.Since(r.startedAt).Round(time.Second).String(),
		Events:                   r.eventCount.Load(),
		Findings:                 r.findingCount.Load(),
		Errors:                   r.errorCount.Load(),
		Sources:                  sourceCount,
		FileSources:              len(r.tailers),
		NativeSources:            len(r.nativeSources),
		NativeEvents:             r.nativeEventCount.Load(),
		AuditActiveSerials:       auditStats.ActiveSerials,
		AuditAssembledEvents:     auditStats.AssembledEvents,
		AuditIncompleteGroups:    auditStats.IncompleteAssemblies,
		AuditDroppedRecords:      auditStats.DroppedRecords,
		AIEnabled:                r.cfg.AI.Enabled,
		AI:                       r.AIStatus(),
		InventoryEnabled:         r.inventoryCollector != nil,
		InventoryRuns:            r.inventoryCount.Load(),
		ProcessGraphEnabled:      r.processGraph != nil,
		ProcessGraphEvents:       r.processGraphEventCount.Load(),
		ProcessGraphActive:       processGraphStats.ActiveProcesses,
		ProcessGraphExited:       processGraphStats.ExitedProcesses,
		ProcessGraphReconciles:   processGraphStats.Reconciliations,
		LastProcessGraphAt:       lastProcessGraphAt,
		ProcessNetworkEnabled:    r.processNetwork != nil,
		ProcessNetworkEvents:     r.processNetworkEventCount.Load(),
		ProcessNetworkSockets:    processNetworkStats.KnownSockets,
		ProcessNetworkScans:      processNetworkStats.Scans,
		ProcessNetworkWarnings:   processNetworkStats.Warnings,
		LastProcessNetworkAt:     lastProcessNetworkAt,
		EBPFSensorEnabled:        ebpfHealth.Enabled,
		EBPFEvents:               r.ebpfEventCount.Load(),
		EBPFLoadedPrograms:       ebpfHealth.LoadedPrograms,
		EBPFAttachedHooks:        ebpfHealth.AttachedHooks,
		EBPFRingBufferLoss:       ebpfHealth.RingBufferLoss,
		EBPFParseErrors:          ebpfHealth.ParseErrors,
		EBPFEventsPerSecond:      ebpfHealth.EventsPerSecond,
		EBPFThrottledEvents:      ebpfHealth.ThrottledEvents,
		EBPFLastEventAt:          ebpfLastEventAt,
		EBPFFallbackReason:       ebpfHealth.FallbackReason,
		EBPFHelperQueueLoss:      ebpfHelperQueueLoss,
		LastInventoryAt:          lastInventoryAt,
		InventoryInterval:        r.cfg.Inventory.Interval,
		TransportEnabled:         r.transportSender != nil,
		TransportPending:         transportStats.Pending,
		TransportPendingBytes:    transportStats.PendingBytes,
		TransportDeadLetter:      transportStats.DeadLetter,
		TransportDeadLetterBytes: transportStats.DeadLetterBty,
		TransportSent:            r.transportSentCount.Load(),
		TransportErrors:          r.transportErrorCount.Load(),
		TransportBackpressure:    r.transportOutbox != nil && transportStats.Pending >= r.cfg.Transport.PendingWarn,
		LastTransportSuccessAt:   lastTransportSuccessAt,
		CertificateAutoRenew:     r.cfg.Transport.Enabled && r.cfg.Transport.AutoRenew,
		CertificateExpiresAt:     certificateExpiresAt,
		CertificateRenewals:      r.certificateRenewalCount.Load(),
		LastCertificateRenewAt:   lastCertificateRenewAt,
		Build:                    buildinfo.Current(),
		SafetyModel:              "AI may analyze evidence; only typed tools behind deterministic policy may act",
	}
	if r.protection != nil {
		protectionStatus := r.protection.Status()
		status.Protection = &protectionStatus
	}
	return status
}

func (r *Runtime) Close() error {
	return r.journal.Close()
}
