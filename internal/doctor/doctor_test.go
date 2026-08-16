//go:build linux

package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
)

func TestOutboxCheckIsReadOnlyAndBounded(t *testing.T) {
	directory := t.TempDir()
	check := outboxCheck(directory)
	if check.Status != Pass {
		t.Fatalf("missing outbox should be healthy and not created: %#v", check)
	}
	if _, err := os.Stat(filepath.Join(directory, "outbox")); !os.IsNotExist(err) {
		t.Fatal("doctor mutated the outbox")
	}
}

func TestPermissionCheckRejectsWorldWritablePath(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "agent.json")
	policyPath := filepath.Join(directory, "policy.json")
	for _, path := range []string{configPath, policyPath} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	check := permissionCheck(configPath, config.Config{DataDir: directory, Tools: config.ToolPolicy{PolicyFile: policyPath}})
	if check.Status != Fail {
		t.Fatalf("world-writable data path was accepted: %#v", check)
	}
}

func TestBoundedCommandOutputCapsMemory(t *testing.T) {
	output := &boundedCommandOutput{maximum: 4}
	if written, err := output.Write([]byte("123456")); err != nil || written != 6 {
		t.Fatalf("unexpected bounded writer result: written=%d err=%v", written, err)
	}
	if !output.exceeded || string(output.content) != "1234" {
		t.Fatalf("bounded writer did not cap output: %#v", output)
	}
}
