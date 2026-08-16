package processgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestProcessGUIDIsDeterministicAndResistsPIDReuse(t *testing.T) {
	first := ProcessGUID("boot-hash", 42, 100)
	if first == "" || !strings.HasPrefix(first, "proc_") || len(first) != len("proc_")+64 {
		t.Fatalf("unexpected process GUID: %q", first)
	}
	if first != ProcessGUID("boot-hash", 42, 100) {
		t.Fatal("process GUID must be deterministic")
	}
	if first == ProcessGUID("boot-hash", 42, 101) || first == ProcessGUID("other-boot", 42, 100) {
		t.Fatal("process GUID did not distinguish PID reuse or reboot")
	}
}

func TestParseProcStatHandlesParenthesesAndStartTicks(t *testing.T) {
	fields := make([]string, 20)
	fields[0] = "S"
	fields[1] = "7"
	for index := 2; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields[19] = "12345"
	stat, err := parseProcStat("42 (worker (odd)) " + strings.Join(fields, " ") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if stat.pid != 42 || stat.ppid != 7 || stat.startTicks != 12345 {
		t.Fatalf("unexpected stat parse: %#v", stat)
	}
}

func TestParseContainerID(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	if got := parseContainerID("0::/system.slice/docker-" + containerID + ".scope\n"); got != containerID {
		t.Fatalf("unexpected Docker container ID: %q", got)
	}
	if got := parseContainerID("0::/user.slice/user-1000.slice"); got != "" {
		t.Fatalf("unexpected container ID for host cgroup: %q", got)
	}
}

func TestReconcilePersistsParentCorrelationAndPIDReuse(t *testing.T) {
	procRoot, statePath := makeFakeProcRoot(t)
	writeFakeProcess(t, procRoot, 100, 1, 1000, "parent", "/usr/bin/parent", "parent --serve", "0::/system.slice/parent.service")
	writeFakeProcess(t, procRoot, 200, 100, 2000, "child", "/usr/bin/child", "child --password secret", "0::/system.slice/docker-"+strings.Repeat("b", 64)+".scope")
	graph, err := Open(Options{ProcRoot: procRoot, StatePath: statePath, MaxProcesses: 16, MaxExitedProcesses: 16, MaxCommandLineBytes: 1024, MaxExecutableHashBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 2 {
		t.Fatalf("expected two recovered start events, got %d", len(batch.Events))
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state was committed before evidence acknowledgement: %v", err)
	}
	replayed, err := graph.Reconcile(context.Background())
	if err != nil || len(replayed.Events) != len(batch.Events) || replayed.Events[0].ID != batch.Events[0].ID {
		t.Fatalf("unacknowledged lifecycle evidence was not replayable: events=%#v err=%v", replayed.Events, err)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(statePath); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("process graph checkpoint is not private: info=%v err=%v", info, err)
	}
	stats := graph.Stats()
	if stats.ActiveProcesses != 2 || stats.ObservedStarts != 2 {
		t.Fatalf("unexpected graph stats after acknowledgement: %#v", stats)
	}
	processes := processMap(graph.state.Active)
	parent := findByPID(processes, 100)
	child := findByPID(processes, 200)
	if child.ParentProcessGUID != parent.ProcessGUID {
		t.Fatalf("parent correlation missing: child=%#v parent=%#v", child, parent)
	}
	if child.ContainerID != strings.Repeat("b", 64) || child.ExecutableSHA256 == "" || runtime.GOOS != "windows" && (child.ExecutableInode == 0 || child.ExecutableDevice == 0) || child.StartedAt.IsZero() {
		t.Fatalf("incomplete Linux process metadata: %#v", child)
	}
	if child.UID != 1000 || child.EUID != 1001 || child.GID != 2000 || child.EGID != 2001 || child.LoginUID != "1000" || child.Session != "17" || child.Namespaces["pid"] == "" || child.Capabilities["CapEff"] == "" {
		t.Fatalf("Linux identity or namespace metadata is incomplete: %#v", child)
	}
	if strings.Contains(child.CommandLine, "secret") {
		t.Fatalf("process graph persisted an unredacted command-line secret: %q", child.CommandLine)
	}

	event := model.Event{Process: model.ProcessContext{PID: 200, Image: child.Executable}}
	graph.Enrich(&event)
	if event.Process.ProcessGUID != child.ProcessGUID || event.Process.ParentProcessGUID != parent.ProcessGUID || event.Process.ContainerID != child.ContainerID {
		t.Fatalf("process event was not safely enriched: %#v", event.Process)
	}
	unknownImage := model.Event{Process: model.ProcessContext{PID: 200}}
	graph.Enrich(&unknownImage)
	if unknownImage.Process.ProcessGUID != "" {
		t.Fatalf("PID-only event was enriched despite PID reuse risk: %#v", unknownImage.Process)
	}
	if resolved, ok := graph.LookupByBootTime(200, 2000*uint64(time.Second)/100); !ok || resolved.ProcessGUID != child.ProcessGUID {
		t.Fatalf("eBPF boot-time identity was not resolved safely: %#v ok=%t", resolved, ok)
	}
	if _, ok := graph.LookupByBootTime(200, 4000*uint64(time.Second)/100); ok {
		t.Fatal("mismatched eBPF boot-time identity was accepted")
	}
	if snapshot, ok := graph.Snapshot(200, 2000); !ok || snapshot.ProcessGUID != child.ProcessGUID {
		t.Fatalf("exact process snapshot was not available: %#v ok=%t", snapshot, ok)
	}

	if err := os.RemoveAll(filepath.Join(procRoot, "200")); err != nil {
		t.Fatal(err)
	}
	writeFakeProcess(t, procRoot, 200, 100, 3000, "replacement", "/usr/bin/replacement", "replacement", "0::/")
	batch, err = graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 2 || batch.Events[0].Kind != "process.exit" || batch.Events[1].Kind != "process.start" {
		t.Fatalf("PID reuse did not yield an exit then a distinct start: %#v", batch.Events)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	replacement := findByPID(processMap(graph.state.Active), 200)
	if replacement.ProcessGUID == child.ProcessGUID || replacement.StartTimeTicks != 3000 {
		t.Fatalf("PID reuse retained old process identity: %#v", replacement)
	}
	if graph.Stats().ExitedProcesses != 1 {
		t.Fatalf("expected one retained exit: %#v", graph.Stats())
	}

	reopened, err := Open(Options{ProcRoot: procRoot, StatePath: statePath, MaxProcesses: 16, MaxExitedProcesses: 16, MaxCommandLineBytes: 1024, MaxExecutableHashBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	batch, err = reopened.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 0 {
		t.Fatalf("persistent graph re-emitted acknowledged processes: %#v", batch.Events)
	}
}

func TestProcessGraphBoundsCommandLineReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cmdline")
	if err := os.WriteFile(path, []byte(strings.Repeat("a", 600)), 0o600); err != nil {
		t.Fatal(err)
	}
	value, truncated, err := readCommandLine(path, 256)
	if err != nil || !truncated || len(value) != 256 {
		t.Fatalf("command line was not bounded: length=%d truncated=%t err=%v", len(value), truncated, err)
	}
	if _, err := Open(Options{ProcRoot: "/proc", StatePath: filepath.Join(t.TempDir(), "state.json"), MaxProcesses: 16385}); err == nil {
		t.Fatal("expected unsafe process graph options to be rejected")
	}
}

func TestReconcileDoesNotMarkExitWhenScanIsCapped(t *testing.T) {
	procRoot, statePath := makeFakeProcRoot(t)
	writeFakeProcess(t, procRoot, 10, 1, 100, "first", "/usr/bin/first", "first", "0::/")
	writeFakeProcess(t, procRoot, 20, 1, 200, "second", "/usr/bin/second", "second", "0::/")
	graph, err := Open(Options{ProcRoot: procRoot, StatePath: statePath, MaxProcesses: 2, MaxExitedProcesses: 4, MaxCommandLineBytes: 1024, MaxExecutableHashBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	writeFakeProcess(t, procRoot, 30, 1, 300, "third", "/usr/bin/third", "third", "0::/")
	batch, err = graph.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range batch.Events {
		if event.Kind == "process.exit" {
			t.Fatalf("capped scan inferred an unsafe exit: %#v", event)
		}
	}
}

func makeFakeProcRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []string{"sys/kernel/random", "self"} {
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

func writeFakeProcess(t *testing.T, root string, pid, ppid int, ticks uint64, name, executable, commandLine, cgroup string) {
	t.Helper()
	base := filepath.Join(root, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(filepath.Join(base, "ns"), 0o700); err != nil {
		t.Fatal(err)
	}
	fields := make([]string, 20)
	fields[0] = "S"
	fields[1] = fmt.Sprintf("%d", ppid)
	for index := 2; index < len(fields); index++ {
		fields[index] = "0"
	}
	fields[19] = fmt.Sprintf("%d", ticks)
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))), 0o600); err != nil {
		t.Fatal(err)
	}
	status := "Name:\t" + name + "\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\nCapEff:\t0000000000000000\n"
	if err := os.WriteFile(filepath.Join(base, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "cmdline"), []byte(strings.ReplaceAll(commandLine, " ", "\x00")+"\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "loginuid"), []byte("1000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "sessionid"), []byte("17\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "cgroup"), []byte(cgroup+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"mnt", "net", "pid"} {
		if err := os.Symlink(namespace+":["+fmt.Sprintf("%d", pid)+"]", filepath.Join(base, "ns", namespace)); err != nil {
			t.Fatal(err)
		}
	}
	executableFile := filepath.Join(root, fmt.Sprintf("binary-%d-%d", pid, ticks))
	if err := os.WriteFile(executableFile, []byte("binary "+name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(executableFile, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
}

func findByPID(values map[string]Process, pid int) Process {
	for _, process := range values {
		if process.PID == pid {
			return process
		}
	}
	return Process{}
}
