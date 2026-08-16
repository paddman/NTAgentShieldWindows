package responseexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/identity"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestLocalExecutorVerifiesLeaseAndDurablyReplaysResult(t *testing.T) {
	directory := t.TempDir()
	_, identityPath, err := identity.Ensure(directory)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustPath := writeResponseTrustRoot(t, publicKey)
	policyPath := filepath.Join(directory, "policy.json")
	policy := `{"version":"1","deny_tools":["shell.exec","cmd.exec","powershell.exec"],"auto_allow_tools":[],"approval_required_tools":["host.isolate","process.terminate","file.quarantine","firewall.block","firewall.port"],"never_allow_destructive":true,"deny_untrusted_state_write":true,"max_action_ttl_seconds":300}`
	if err := os.WriteFile(policyPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	executor, err := NewLocalExecutor(ExecutorOptions{
		DataDir: directory, AgentID: "agent-a", TenantID: "tenant-a", PolicyFile: policyPath,
		AllowedPaths: []string{directory}, ControlEndpoint: "https://control.example", IdentityKeyFile: identityPath, TrustRootFile: trustPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lease := Lease{
		Schema: responseSchema, ActionID: "rsp-helper-1", TenantID: "tenant-a", AgentID: "agent-a",
		Tool: "unknown.response", Args: map[string]interface{}{}, Reason: "test typed rejection", Risk: model.RiskContain,
		RequestedBy: "operator-a", RequestedAt: now.Add(-time.Minute), ApprovedBy: "operator-b", ApprovedAt: now.Add(-30 * time.Second),
		ActionExpiresAt: now.Add(4 * time.Minute), LeaseIssuedAt: now.Add(-time.Second), LeaseExpiresAt: now.Add(time.Minute),
	}
	bundle := signLease(t, privateKey, lease)
	first, verified, err := executor.Execute(t.Context(), bundle, now)
	if err != nil || verified.ActionID != lease.ActionID {
		t.Fatalf("execute signed lease: verified=%#v err=%v", verified, err)
	}
	var result ResultPayload
	if err := json.Unmarshal(first, &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "rejected" || result.ActionID != lease.ActionID {
		t.Fatalf("unexpected typed rejection result: %#v", result)
	}
	second, _, err := executor.Execute(t.Context(), bundle, now)
	if err != nil || string(second) != string(first) {
		t.Fatalf("durable replay changed result: first=%s second=%s err=%v", first, second, err)
	}
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	if _, _, err := executor.Execute(t.Context(), signLease(t, attacker, lease), now); err == nil {
		t.Fatal("response helper accepted an invalid signer")
	}
}
