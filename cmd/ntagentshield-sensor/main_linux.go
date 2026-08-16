//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/buildinfo"
	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/helperipc"
	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
	ebpfsensor "github.com/paddman/NTAgentShieldWindows/internal/sensor/ebpf"
	"github.com/paddman/NTAgentShieldWindows/internal/sensoripc"
)

func main() {
	configPath := flag.String("config", "/etc/ntagentshield/agent.json", "path to local Agent JSON configuration")
	allowedUser := flag.String("allow-user", "ntagentshield-agent", "exact unprivileged core user allowed by SO_PEERCRED")
	stateDir := flag.String("state-dir", "/run/ntagentshield-sensor", "ephemeral sensor process-context directory")
	prepareTraceFS := flag.Bool("prepare-tracefs", false, "perform the fixed privileged tracefs remount and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	if *prepareTraceFS {
		if err := ebpfsensor.PrepareTraceFS(); err != nil {
			fatal("prepare fixed tracefs sensor access", err)
		}
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("load configuration", err)
	}
	if !cfg.PrivilegeSeparation.Enabled || !cfg.EBPFSensor.Enabled {
		fatal("start sensor helper", fmt.Errorf("privilege separation and eBPF sensor must be enabled"))
	}
	uid, err := lookupUID(*allowedUser)
	if err != nil {
		fatal("resolve allowed core user", err)
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fatal("create sensor state directory", err)
	}
	graph, err := processgraph.Open(processgraph.Options{
		StatePath:    filepath.Join(*stateDir, "process-context.json"),
		MaxProcesses: cfg.ProcessGraph.MaxProcesses, MaxExitedProcesses: 0,
		MaxCommandLineBytes:    cfg.ProcessGraph.MaxCommandLineBytes,
		MaxExecutableHashBytes: cfg.ProcessGraph.MaxExecutableHashBytes,
	})
	if err != nil {
		fatal("initialize sensor process context", err)
	}
	if batch, reconcileErr := graph.Reconcile(context.Background()); reconcileErr == nil {
		_ = batch.Acknowledge()
	}
	sensor, err := ebpfsensor.New(graph, ebpfsensor.Options{RingBufferBytes: cfg.EBPFSensor.RingBufferBytes, MaxEventsPerSec: cfg.EBPFSensor.MaxEventsPerSec})
	if err != nil {
		fatal("initialize fixed CO-RE sensor", err)
	}
	defer sensor.Close()
	broker, err := sensoripc.NewBroker(8192, sensor.Health)
	if err != nil {
		fatal("initialize bounded sensor queue", err)
	}
	timeout, err := time.ParseDuration(cfg.PrivilegeSeparation.RequestTimeout)
	if err != nil {
		fatal("parse helper timeout", err)
	}
	logger := log.New(os.Stdout, "ntagentshield-sensor ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	server, err := sensoripc.NewServer(sensoripc.ServerOptions{
		Broker: broker, SocketPath: cfg.PrivilegeSeparation.SensorSocket, SocketMode: 0o660,
		AllowedUIDs: []uint32{uid}, MaxMessageSize: cfg.PrivilegeSeparation.MaxMessageBytes, Timeout: timeout,
		Audit: func(record helperipc.AuditRecord) {
			encoded, _ := json.Marshal(record)
			logger.Printf("ipc_audit=%s", encoded)
		},
	})
	if err != nil {
		fatal("initialize sensor helper socket", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := sensor.Start(ctx, broker.Add); err != nil {
		logger.Printf("fixed CO-RE sensor unavailable: %v; auditd/journald fallback remains active", err)
	}
	go reconcile(ctx, graph, cfg.ProcessGraph.ReconcileInterval, logger)
	logger.Printf("starting telemetry-only helper socket=%s allowed_uid=%d", cfg.PrivilegeSeparation.SensorSocket, uid)
	if err := server.Run(ctx); err != nil {
		fatal("run sensor helper", err)
	}
}

func reconcile(ctx context.Context, graph *processgraph.Graph, intervalText string, logger *log.Logger) {
	interval, err := time.ParseDuration(intervalText)
	if err != nil {
		logger.Printf("process context reconciliation disabled: %v", err)
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			batch, err := graph.Reconcile(ctx)
			if err != nil {
				logger.Printf("process context reconciliation error: %v", err)
				continue
			}
			if err := batch.Acknowledge(); err != nil {
				logger.Printf("process context checkpoint error: %v", err)
			}
		}
	}
}

func lookupUID(name string) (uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(value), nil
}

func fatal(operation string, err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
	os.Exit(1)
}
