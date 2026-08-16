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
	"github.com/paddman/NTAgentShieldWindows/internal/identity"
	"github.com/paddman/NTAgentShieldWindows/internal/responseexec"
)

func main() {
	configPath := flag.String("config", "/etc/ntagentshield/agent.json", "path to local Agent JSON configuration")
	allowedUser := flag.String("allow-user", "ntagentshield-agent", "exact unprivileged core user allowed by SO_PEERCRED")
	stateDir := flag.String("state-dir", "/var/lib/ntagentshield-response", "restricted response ledger and containment state directory")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("load configuration", err)
	}
	if !cfg.PrivilegeSeparation.Enabled {
		fatal("start response helper", fmt.Errorf("privilege_separation.enabled must be true"))
	}
	uid, err := lookupUID(*allowedUser)
	if err != nil {
		fatal("resolve allowed core user", err)
	}
	timeout, err := time.ParseDuration(cfg.PrivilegeSeparation.RequestTimeout)
	if err != nil {
		fatal("parse helper timeout", err)
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		fatal("create response state directory", err)
	}
	_, responseKey, err := identity.Ensure(*stateDir)
	if err != nil {
		fatal("initialize response state identity", err)
	}
	executor, err := responseexec.NewLocalExecutor(responseexec.ExecutorOptions{
		DataDir: *stateDir, AgentID: cfg.AgentID, TenantID: cfg.TenantID,
		PolicyFile: cfg.Tools.PolicyFile, AllowedPaths: cfg.Tools.AllowedPaths,
		ControlEndpoint: cfg.Transport.Endpoint, IdentityKeyFile: responseKey,
		TrustRootFile: filepath.Join(cfg.DataDir, "trust", "response-signing.pub"),
	})
	if err != nil {
		fatal("initialize privileged response executor", err)
	}
	logger := log.New(os.Stdout, "ntagentshield-response ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	server, err := responseexec.NewHelperServer(responseexec.HelperServerOptions{
		Executor: executor, SocketPath: cfg.PrivilegeSeparation.ResponseSocket, SocketMode: 0o660,
		AllowedUIDs: []uint32{uid}, MaxMessageSize: cfg.PrivilegeSeparation.MaxMessageBytes, Timeout: timeout,
		Audit: func(record helperipc.AuditRecord) {
			encoded, _ := json.Marshal(record)
			logger.Printf("ipc_audit=%s", encoded)
		},
	})
	if err != nil {
		fatal("initialize response helper socket", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Printf("starting fixed typed response helper socket=%s allowed_uid=%d", cfg.PrivilegeSeparation.ResponseSocket, uid)
	if err := server.Run(ctx); err != nil {
		fatal("run response helper", err)
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
