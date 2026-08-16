package hardening

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxSystemdPrivilegeBoundaries(t *testing.T) {
	directory := filepath.Join("..", "..", "packaging", "systemd")
	agent := readUnit(t, directory, "ntagentshield-agent.service")
	sensor := readUnit(t, directory, "ntagentshield-sensor.service")
	response := readUnit(t, directory, "ntagentshield-response.service")

	for name, unit := range map[string]string{"agent": agent, "sensor": sensor, "response": response} {
		for _, invariant := range []string{"NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "PrivateTmp=true", "SystemCallArchitectures=native"} {
			if !strings.Contains(unit, invariant) {
				t.Fatalf("%s unit is missing %s", name, invariant)
			}
		}
	}
	if !strings.Contains(agent, "User=ntagentshield-agent") || !strings.Contains(agent, "CapabilityBoundingSet=\n") || !strings.Contains(agent, "AmbientCapabilities=\n") {
		t.Fatal("Core Agent does not have an empty capability set")
	}
	if !strings.Contains(sensor, "User=ntagentshield-sensor") || !strings.Contains(sensor, "CapabilityBoundingSet=CAP_BPF CAP_PERFMON") || strings.Contains(sensor, "CAP_SYS_ADMIN") {
		t.Fatal("sensor capability boundary is not minimal")
	}
	if !strings.Contains(response, "User=ntagentshield-response") {
		t.Fatal("response helper does not use its dedicated identity")
	}
	for _, capability := range []string{"CAP_NET_ADMIN", "CAP_KILL", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH"} {
		if !strings.Contains(response, capability) {
			t.Fatalf("response helper is missing %s", capability)
		}
	}
	if strings.Contains(response, "CAP_SYS_ADMIN") || strings.Contains(response, "CAP_BPF") {
		t.Fatal("response helper includes unrelated telemetry or administrative capabilities")
	}
}

func readUnit(t *testing.T, directory, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
