//go:build linux

// Package doctor performs bounded, read-only Linux deployment diagnostics.
package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/enrollment"
	"golang.org/x/sys/unix"
)

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
}

type Report struct {
	Timestamp time.Time `json:"timestamp"`
	Checks    []Check   `json:"checks"`
	Passed    int       `json:"passed"`
	Warnings  int       `json:"warnings"`
	Failed    int       `json:"failed"`
}

func Run(ctx context.Context, cfg config.Config, configPath string) Report {
	checks := []Check{
		kernelCheck(), fileCheck("kernel_btf", "/sys/kernel/btf/vmlinux", false),
		fileCheck("auditd_log", auditPath(cfg), true), fileCheck("journald_socket", "/run/systemd/journal/socket", false),
		nftCheck(ctx), capabilityCheck(), permissionCheck(configPath, cfg), certificateCheck(cfg), connectivityCheck(ctx, cfg), outboxCheck(cfg.DataDir),
	}
	report := Report{Timestamp: time.Now().UTC(), Checks: checks}
	for _, check := range checks {
		switch check.Status {
		case Pass:
			report.Passed++
		case Warn:
			report.Warnings++
		case Fail:
			report.Failed++
		}
	}
	return report
}

func kernelCheck() Check {
	var value unix.Utsname
	if err := unix.Uname(&value); err != nil {
		return Check{"kernel", Fail, err.Error()}
	}
	release := strings.TrimRight(string(value.Release[:]), "\x00")
	parts := strings.SplitN(release, ".", 3)
	major, minor := 0, 0
	if len(parts) >= 2 {
		major, _ = strconv.Atoi(parts[0])
		minor, _ = strconv.Atoi(parts[1])
	}
	if major < 5 || major == 5 && minor < 8 {
		return Check{"kernel", Warn, release + " is older than the supported eBPF 5.8 baseline"}
	}
	return Check{"kernel", Pass, release}
}

func fileCheck(name, path string, requireReadable bool) Check {
	info, err := os.Stat(path)
	if err != nil {
		return Check{name, Warn, err.Error()}
	}
	if requireReadable {
		file, err := os.Open(path)
		if err != nil {
			return Check{name, Warn, "exists but is not readable: " + err.Error()}
		}
		_ = file.Close()
	}
	return Check{name, Pass, fmt.Sprintf("%s mode=%s", path, info.Mode())}
}

func auditPath(cfg config.Config) string {
	for _, source := range cfg.NativeSources {
		if source.Enabled && (source.Kind == "auditd" || source.Kind == "linux_auditd") && source.Path != "" {
			return source.Path
		}
	}
	return "/var/log/audit/audit.log"
}

func nftCheck(ctx context.Context) Check {
	commandContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	command := exec.CommandContext(commandContext, "nft", "--version")
	output := &boundedCommandOutput{maximum: 4096}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if output.exceeded {
		return Check{"nftables", Fail, "version output exceeded fixed bound"}
	}
	if err != nil {
		message := strings.TrimSpace(string(output.content))
		if message == "" {
			message = err.Error()
		}
		return Check{"nftables", Warn, message}
	}
	return Check{"nftables", Pass, strings.TrimSpace(string(output.content))}
}

type boundedCommandOutput struct {
	content  []byte
	maximum  int
	exceeded bool
}

func (b *boundedCommandOutput) Write(content []byte) (int, error) {
	remaining := b.maximum - len(b.content)
	if remaining <= 0 {
		b.exceeded = true
		return len(content), nil
	}
	if len(content) > remaining {
		b.content = append(b.content, content[:remaining]...)
		b.exceeded = true
		return len(content), nil
	}
	b.content = append(b.content, content...)
	return len(content), nil
}

func capabilityCheck() Check {
	content, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return Check{"capabilities", Warn, err.Error()}
	}
	effective := uint64(0)
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			encoded := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			bytes, decodeErr := hex.DecodeString(encoded)
			if decodeErr == nil {
				for _, value := range bytes {
					effective = effective<<8 | uint64(value)
				}
			}
		}
	}
	has := func(capability uint) bool { return effective&(uint64(1)<<capability) != 0 }
	if has(unix.CAP_BPF) && has(unix.CAP_PERFMON) {
		return Check{"capabilities", Pass, "current context has CAP_BPF and CAP_PERFMON"}
	}
	return Check{"capabilities", Warn, "current context lacks CAP_BPF+CAP_PERFMON; verify ntagentshield-sensor.service rather than granting caps to Core"}
}

func permissionCheck(configPath string, cfg config.Config) Check {
	paths := []string{configPath, cfg.DataDir, cfg.Tools.PolicyFile}
	if cfg.PrivilegeSeparation.Enabled {
		paths = append(paths, filepath.Dir(cfg.PrivilegeSeparation.SensorSocket), filepath.Dir(cfg.PrivilegeSeparation.ResponseSocket))
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return Check{"filesystem_permissions", Warn, fmt.Sprintf("%s: %v", path, err)}
		}
		if info.Mode().Perm()&0o002 != 0 {
			return Check{"filesystem_permissions", Fail, path + " is world-writable"}
		}
	}
	return Check{"filesystem_permissions", Pass, "configured paths exist and are not world-writable"}
}

func certificateCheck(cfg config.Config) Check {
	if !cfg.Transport.Enabled {
		return Check{"certificate", Warn, "signed mTLS transport is disabled"}
	}
	content, err := tls.LoadX509KeyPair(cfg.Transport.CertFile, cfg.Transport.KeyFile)
	if err != nil {
		return Check{"certificate", Fail, err.Error()}
	}
	if len(content.Certificate) == 0 {
		return Check{"certificate", Fail, "client certificate chain is empty"}
	}
	certificate, err := x509.ParseCertificate(content.Certificate[0])
	if err != nil {
		return Check{"certificate", Fail, err.Error()}
	}
	remaining := time.Until(certificate.NotAfter)
	if remaining <= 0 {
		return Check{"certificate", Fail, "client certificate expired at " + certificate.NotAfter.UTC().Format(time.RFC3339)}
	}
	status := Pass
	if remaining < 7*24*time.Hour {
		status = Warn
	}
	return Check{"certificate", status, fmt.Sprintf("valid until %s (%s remaining)", certificate.NotAfter.UTC().Format(time.RFC3339), remaining.Round(time.Hour))}
}

func connectivityCheck(ctx context.Context, cfg config.Config) Check {
	if !cfg.Transport.Enabled {
		return Check{"control_plane_connectivity", Warn, "transport disabled"}
	}
	tlsConfig, err := enrollment.ClientTLSConfig(cfg.Transport.CertFile, cfg.Transport.KeyFile, cfg.Transport.CAFile, cfg.Transport.ServerName)
	if err != nil {
		return Check{"control_plane_connectivity", Fail, err.Error()}
	}
	client := http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true}}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, cfg.Transport.Endpoint, nil)
	if err != nil {
		return Check{"control_plane_connectivity", Fail, err.Error()}
	}
	response, err := client.Do(request)
	if err != nil {
		return Check{"control_plane_connectivity", Warn, err.Error()}
	}
	_ = response.Body.Close()
	return Check{"control_plane_connectivity", Pass, fmt.Sprintf("TLS connected; HTTP %d", response.StatusCode)}
}

func outboxCheck(dataDir string) Check {
	pending := filepath.Join(dataDir, "outbox", "pending")
	directory, err := os.Open(pending)
	if errors.Is(err, os.ErrNotExist) {
		return Check{"outbox", Pass, "no pending outbox directory"}
	}
	if err != nil {
		return Check{"outbox", Warn, err.Error()}
	}
	defer directory.Close()
	count := 0
	for count <= 10000 {
		entries, readErr := directory.ReadDir(min(256, 10001-count))
		count += len(entries)
		if count > 10000 {
			return Check{"outbox", Warn, "more than 10000 pending objects exceed warning threshold"}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return Check{"outbox", Warn, readErr.Error()}
		}
	}
	return Check{"outbox", Pass, fmt.Sprintf("%d pending objects", count)}
}
