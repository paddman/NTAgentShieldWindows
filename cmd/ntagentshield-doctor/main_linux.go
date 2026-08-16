//go:build linux

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/doctor"
)

func main() {
	configPath := flag.String("config", "/etc/ntagentshield/agent.json", "path to local Agent JSON configuration")
	timeout := flag.Duration("timeout", 10*time.Second, "overall read-only diagnostic timeout")
	flag.Parse()
	if *timeout < time.Second || *timeout > time.Minute {
		fatal(fmt.Errorf("timeout must be between 1s and 1m"))
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report := doctor.Run(ctx, cfg, *configPath)
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fatal(err)
	}
	if report.Failed > 0 {
		os.Exit(2)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
