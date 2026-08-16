package networkinventory

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
)

func TestParseProcAddressAndSocketInode(t *testing.T) {
	address, port, err := parseProcAddress("0100007F:1F90", false)
	if err != nil || address != "127.0.0.1" || port != 8080 {
		t.Fatalf("unexpected IPv4 socket address: %s:%d err=%v", address, port, err)
	}
	if inode, ok := socketInode("socket:[12345]"); !ok || inode != "12345" {
		t.Fatalf("unexpected socket inode parse: %q %t", inode, ok)
	}
	if socketState(true, "0A") != "LISTEN" || socketState(false, "07") != "UNCONN" {
		t.Fatal("socket state normalization failed")
	}
}

func TestReadDirectoryEntriesIsBounded(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"1", "2", "3"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, capped, err := readDirectoryEntries(directory, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !capped {
		t.Fatalf("directory scan was not bounded: entries=%d capped=%t", len(entries), capped)
	}
}

func TestNetworkAttributionUsesProcessGUIDAndStartTicks(t *testing.T) {
	procRoot, statePath := fakeProcRoot(t)
	writeProcess(t, procRoot, 42, 1, 1000, "worker")
	writeSocketTable(t, procRoot, "12345")
	if err := os.MkdirAll(filepath.Join(procRoot, "42", "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(procRoot, "42", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	graph, err := processgraph.Open(processgraph.Options{ProcRoot: procRoot, StatePath: statePath, MaxProcesses: 8, MaxExitedProcesses: 8, MaxCommandLineBytes: 1024, MaxExecutableHashBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	graphBatch, err := graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := graphBatch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	collector, err := New(graph, Options{ProcRoot: procRoot, MaxProcesses: 8, MaxSockets: 8, MaxFDs: 16})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := collector.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 1 {
		t.Fatalf("expected one attributed listener, got %#v", batch.Events)
	}
	event := batch.Events[0]
	if event.Kind != "network.listen" || event.Process.ProcessGUID == "" || event.Process.PID != 42 || event.Process.Image == "" || event.Network.SourceIP != "127.0.0.1" || event.Network.SourcePort != 8080 || event.Network.Protocol != "tcp" {
		t.Fatalf("incomplete attributed network event: %#v", event)
	}
	replayed, err := collector.Reconcile(context.Background())
	if err != nil || len(replayed.Events) != 1 || replayed.Events[0].ID != event.ID {
		t.Fatalf("unacknowledged socket evidence was not replayed: events=%#v err=%v", replayed.Events, err)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	batch, err = collector.Reconcile(context.Background())
	if err != nil || len(batch.Events) != 0 {
		t.Fatalf("known socket was re-emitted without a change: events=%#v err=%v", batch.Events, err)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}

	// Simulate PID reuse before graph reconciliation. The socket must not be
	// attributed to the old process identity solely because the PID matches.
	writeProcess(t, procRoot, 42, 1, 2000, "replacement")
	batch, err = collector.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 0 {
		t.Fatalf("PID-reused socket was attributed without matching start ticks: %#v", batch.Events)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}

	graphBatch, err = graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := graphBatch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	batch, err = collector.Reconcile(context.Background())
	if err != nil || len(batch.Events) != 1 {
		t.Fatalf("reconciled replacement socket was not emitted: events=%#v err=%v", batch.Events, err)
	}
	if batch.Events[0].Process.ProcessGUID == event.Process.ProcessGUID {
		t.Fatalf("PID reuse retained the old process GUID: %q", batch.Events[0].Process.ProcessGUID)
	}
}

func fakeProcRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"sys/kernel/random", "self", "net"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "sys/kernel/random/boot_id"), []byte("11111111-2222-3333-4444-555555555555\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(t.TempDir(), "process-graph.json")
}

func writeProcess(t *testing.T, root string, pid, ppid int, ticks uint64, name string) {
	t.Helper()
	base := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	fields[0], fields[1] = "S", fmt.Sprintf("%d", ppid)
	for index := 2; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields[19] = fmt.Sprintf("%d", ticks)
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "status"), []byte("Name:\t"+name+"\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "cmdline"), []byte(name+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, fmt.Sprintf("binary-%d-%d", pid, ticks))
	if err := os.WriteFile(executable, []byte(name), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(base, "exe"))
	if err := os.Symlink(executable, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
}

func writeSocketTable(t *testing.T, root, inode string) {
	t.Helper()
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 " + inode + " 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(filepath.Join(root, "net", "tcp"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(root, "net", file), []byte("header\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
