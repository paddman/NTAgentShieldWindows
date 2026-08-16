//go:build linux

package tools

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/identity"
)

type linuxFakeRunner struct {
	calls    []string
	script   string
	tables   map[string]bool
	elements map[string]bool
}

func (f *linuxFakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	joined := strings.Join(args, " ")
	if joined == "--version" {
		return []byte("nftables v1"), nil
	}
	if strings.HasPrefix(joined, "list table inet ") {
		table := args[len(args)-1]
		if f.tables[table] {
			if table == linuxIsolationTable {
				return []byte(f.script), nil
			}
			return []byte("table exists"), nil
		}
		return nil, errors.New("not found")
	}
	if strings.HasPrefix(joined, "delete table inet ") {
		delete(f.tables, args[len(args)-1])
		return nil, nil
	}
	if strings.HasPrefix(joined, "add element inet ") || strings.HasPrefix(joined, "delete element inet ") {
		if f.elements == nil {
			f.elements = map[string]bool{}
		}
		key := strings.Join(args[3:], "/")
		if strings.HasPrefix(joined, "add element") {
			f.elements[key] = true
		} else {
			delete(f.elements, key)
		}
		return nil, nil
	}
	if strings.HasPrefix(joined, "list set inet ") {
		prefix := strings.Join(args[3:], "/") + "/"
		values := ""
		for key := range f.elements {
			if strings.HasPrefix(key, prefix) {
				parts := strings.Split(key, "/")
				values += " " + parts[len(parts)-2]
			}
		}
		return []byte("elements = {" + values + " }"), nil
	}
	return nil, nil
}

func (f *linuxFakeRunner) RunInput(_ context.Context, input, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.script = input
	if strings.Contains(input, "table inet ntshield_isolation") {
		f.tables[linuxIsolationTable] = true
	}
	if strings.Contains(input, "table inet ntshield_block") {
		f.tables[linuxBlockTable] = true
	}
	if strings.Contains(input, "table inet ntshield_ports") {
		f.tables[linuxPortTable] = true
	}
	return nil, nil
}

func TestLinuxFirewallPortUsesSignedOwnedTableAndVerifies(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}, elements: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	rule := PortRule{Protocol: "TCP", Direction: "inbound", Port: 8443}
	result, err := backend.OpenPort(t.Context(), rule)
	if err != nil || result["verified"] != true {
		t.Fatalf("open port failed: result=%#v err=%v calls=%v", result, err, fake.calls)
	}
	state, err := loadSignedContainmentState(backend.portStatePath(), identityPath, "firewall-ports-linux-nft")
	if err != nil || state.Data["table"] != linuxPortTable {
		t.Fatalf("signed port ownership state invalid: state=%#v err=%v", state, err)
	}
	result, err = backend.ClosePort(t.Context(), rule)
	if err != nil || result["verified"] != true {
		t.Fatalf("close port failed: result=%#v err=%v", result, err)
	}
}

func TestLinuxHostIsolationPreservesControlPlaneAndIsReversible(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath, controlEndpoint: "https://203.0.113.10:9443/v1/agent/events"}
	result, err := backend.Isolate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result["isolated"] != true {
		t.Fatalf("unexpected isolation result: %#v", result)
	}
	for _, expected := range []string{"ip daddr 203.0.113.10 tcp dport 9443 accept", "udp dport 53 accept", "policy drop"} {
		if !strings.Contains(fake.script, expected) {
			t.Fatalf("isolation nft script missing %q:\n%s", expected, fake.script)
		}
	}
	if _, err := loadSignedContainmentState(filepath.Join(dir, "containment", "host-isolation.json"), identityPath, "host-isolation-linux-nft"); err != nil {
		t.Fatalf("signed isolation state invalid: %v", err)
	}
	release, err := backend.Release(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if release["released"] != true {
		t.Fatalf("unexpected release result: %#v", release)
	}
	if fake.tables[linuxIsolationTable] {
		t.Fatal("isolation table should be deleted on release")
	}
}

func TestLinuxFirewallBlockUsesSignedOwnedTable(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	address := netip.MustParseAddr("198.51.100.7")
	blocked, err := backend.Block(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if blocked["verified"] != true {
		t.Fatalf("block was not verified: %#v", blocked)
	}
	joined := strings.Join(fake.calls, "\n")
	if !strings.Contains(joined, "nft add element inet ntshield_block blocked4 { 198.51.100.7 }") {
		t.Fatalf("missing exact blocked element command:\n%s", joined)
	}
	if _, err := loadSignedContainmentState(backend.blockStatePath(), identityPath, "firewall-block-linux-nft"); err != nil {
		t.Fatalf("block table ownership state invalid: %v", err)
	}
	unblocked, err := backend.Unblock(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if unblocked["verified"] != true {
		t.Fatalf("unblock was not verified: %#v", unblocked)
	}
	already, err := backend.Unblock(context.Background(), address)
	if err != nil || already["already_unblocked"] != true || already["verified"] != true {
		t.Fatalf("idempotent unblock failed: result=%#v err=%v", already, err)
	}
}

func TestLinuxHostIsolationRejectsOwnedTableRuleDrift(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath, controlEndpoint: "https://203.0.113.10:9443/v1/agent/events"}
	if _, err := backend.Isolate(t.Context()); err != nil {
		t.Fatal(err)
	}
	fake.script = strings.ReplaceAll(fake.script, "ip daddr 203.0.113.10 tcp dport 9443 accept", "")
	if _, err := backend.Isolate(t.Context()); err == nil || !strings.Contains(err.Error(), "Control Plane exception") {
		t.Fatalf("expected isolation rule drift rejection, got %v", err)
	}
}

func TestLinuxFirewallRefusesUnownedNamedTable(t *testing.T) {
	dir := t.TempDir()
	_, identityPath, err := identity.Ensure(dir)
	if err != nil {
		t.Fatal(err)
	}
	fake := &linuxFakeRunner{tables: map[string]bool{linuxBlockTable: true}}
	backend := &linuxNetworkBackend{runner: fake, dataDir: dir, identityKeyFile: identityPath}
	_, err = backend.Block(context.Background(), netip.MustParseAddr("203.0.113.44"))
	if err == nil || !strings.Contains(err.Error(), "without signed") {
		t.Fatalf("expected unowned table rejection, got %v", err)
	}
}
