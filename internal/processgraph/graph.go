package processgraph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

const (
	defaultMaxProcesses           = 4096
	defaultMaxExitedProcesses     = 4096
	defaultMaxCommandLineBytes    = 8192
	defaultMaxExecutableHashBytes = 256 * 1024 * 1024
	maxStateBytes                 = 64 * 1024 * 1024
)

type Graph struct {
	mu       sync.Mutex
	options  Options
	state    persistedState
	pending  *pendingBatch
	bootTime time.Time
	clockHz  uint64
}

type pendingBatch struct {
	state  persistedState
	events []model.Event
}

type Batch struct {
	Events  []model.Event
	graph   *Graph
	pending *pendingBatch
}

func Open(options Options) (*Graph, error) {
	options = normalizedOptions(options)
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	if options.StatePath == "" || !filepath.IsAbs(options.StatePath) {
		return nil, errors.New("process graph state path must be absolute")
	}
	if _, err := readBootIDHash(options.ProcRoot); err != nil {
		return nil, fmt.Errorf("read Linux boot identifier: %w", err)
	}
	bootTime := readBootTime(options.ProcRoot)
	clockHz := readClockTicks(options.ProcRoot)
	state, err := loadState(options.StatePath, options)
	if err != nil {
		return nil, err
	}
	if state.Version == 0 {
		state.Version = stateVersion
	}
	return &Graph{options: options, state: state, bootTime: bootTime, clockHz: clockHz}, nil
}

func normalizedOptions(options Options) Options {
	if options.ProcRoot == "" {
		options.ProcRoot = "/proc"
	}
	options.ProcRoot = filepath.Clean(options.ProcRoot)
	if options.MaxProcesses == 0 {
		options.MaxProcesses = defaultMaxProcesses
	}
	if options.MaxExitedProcesses == 0 {
		options.MaxExitedProcesses = defaultMaxExitedProcesses
	}
	if options.MaxCommandLineBytes == 0 {
		options.MaxCommandLineBytes = defaultMaxCommandLineBytes
	}
	if options.MaxExecutableHashBytes == 0 {
		options.MaxExecutableHashBytes = defaultMaxExecutableHashBytes
	}
	return options
}

func validateOptions(options Options) error {
	if options.MaxProcesses < 1 || options.MaxProcesses > 16384 {
		return errors.New("process graph max processes must be between 1 and 16384")
	}
	if options.MaxExitedProcesses < 0 || options.MaxExitedProcesses > 16384 {
		return errors.New("process graph max exited processes must be between 0 and 16384")
	}
	if options.MaxCommandLineBytes < 256 || options.MaxCommandLineBytes > 64*1024 {
		return errors.New("process graph max command line bytes must be between 256 and 65536")
	}
	if options.MaxExecutableHashBytes < 1024*1024 || options.MaxExecutableHashBytes > 1024*1024*1024 {
		return errors.New("process graph max executable hash bytes must be between 1 MiB and 1 GiB")
	}
	return nil
}

func (g *Graph) Reconcile(ctx context.Context) (Batch, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pending != nil {
		return Batch{Events: append([]model.Event(nil), g.pending.events...), graph: g, pending: g.pending}, nil
	}
	if err := validateOptions(g.options); err != nil {
		return Batch{}, err
	}
	bootIDHash, err := readBootIDHash(g.options.ProcRoot)
	if err != nil {
		g.state.Stats.ScanErrors++
		return Batch{}, err
	}
	if currentBootTime := readBootTime(g.options.ProcRoot); !currentBootTime.IsZero() {
		g.bootTime = currentBootTime
	}
	if currentClockHz := readClockTicks(g.options.ProcRoot); currentClockHz > 0 {
		g.clockHz = currentClockHz
	}
	scan, err := scanProcesses(ctx, g.options, bootIDHash, g.bootTime, g.clockHz)
	if err != nil {
		g.state.Stats.ScanErrors++
		return Batch{}, err
	}
	next, events := g.nextState(bootIDHash, scan, time.Now().UTC())
	next.Stats.Reconciliations++
	next.Stats.LastReconciled = time.Now().UTC()
	if len(scan.warnings) > 0 {
		next.Stats.ScanErrors += uint64(len(scan.warnings))
	}
	pending := &pendingBatch{state: next, events: events}
	g.pending = pending
	return Batch{Events: append([]model.Event(nil), events...), graph: g, pending: pending}, nil
}

func (g *Graph) nextState(bootIDHash string, scan procScan, now time.Time) (persistedState, []model.Event) {
	next := cloneState(g.state)
	next.Version = stateVersion
	previousBoot := next.BootIDHash
	next.BootIDHash = bootIDHash
	active := processMap(next.Active)
	exited := append([]Process(nil), next.Exited...)
	events := make([]model.Event, 0)
	currentByPID := make(map[int]Process, len(scan.processes))
	for _, process := range scan.processes {
		currentByPID[process.PID] = process
	}
	parentByPID := make(map[int]string, len(scan.processes))
	for _, process := range scan.processes {
		parentByPID[process.PID] = process.ProcessGUID
	}
	if previousBoot != "" && previousBoot != bootIDHash {
		for _, previous := range active {
			if previous.StoppedAt == nil {
				exitedProcess := stopProcess(previous, now, "boot_changed")
				exited = append(exited, exitedProcess)
				events = append(events, processExitEvent(exitedProcess))
			}
		}
		active = map[string]Process{}
	}

	for _, previous := range sortedProcesses(active) {
		guid := previous.ProcessGUID
		current, exists := currentByPID[previous.PID]
		if exists && current.ProcessGUID == guid {
			continue
		}
		if scan.complete && !scan.unresolvedPIDs[previous.PID] {
			exitedProcess := stopProcess(previous, now, "not_observed")
			exited = append(exited, exitedProcess)
			events = append(events, processExitEvent(exitedProcess))
			delete(active, guid)
		}
	}

	for _, current := range scan.processes {
		if parentGUID := parentByPID[current.PPID]; parentGUID != "" && parentGUID != current.ProcessGUID {
			current.ParentProcessGUID = parentGUID
		} else if previousParent := active[current.ProcessGUID].ParentProcessGUID; previousParent != "" {
			current.ParentProcessGUID = previousParent
		}
		previous, exists := active[current.ProcessGUID]
		if exists {
			current.StartedAt = previous.StartedAt
			if current.StartedAt.IsZero() {
				current.StartedAt = now
			}
			current.ObservedAt = now
			active[current.ProcessGUID] = current
			continue
		}
		if current.StartedAt.IsZero() {
			current.StartedAt = now
		}
		current.ObservedAt = now
		active[current.ProcessGUID] = current
		events = append(events, processStartEvent(current))
	}

	next.Active = sortedProcesses(active)
	next.Exited = capExited(exited, g.options.MaxExitedProcesses)
	for _, event := range events {
		if event.Kind == "process.exit" {
			next.Stats.ObservedExits++
		} else {
			next.Stats.ObservedStarts++
		}
	}
	return next, events
}

func (b Batch) Acknowledge() error {
	if b.graph == nil || b.pending == nil {
		return nil
	}
	b.graph.mu.Lock()
	defer b.graph.mu.Unlock()
	if b.graph.pending != b.pending {
		return nil
	}
	if err := saveState(b.graph.options.StatePath, b.pending.state); err != nil {
		return err
	}
	b.graph.state = b.pending.state
	b.graph.pending = nil
	return nil
}

func (g *Graph) Enrich(event *model.Event) {
	if event == nil || event.Process.PID <= 0 || event.Process.Image == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, process := range g.state.Active {
		if process.PID != event.Process.PID {
			continue
		}
		if !event.Timestamp.IsZero() && !process.StartedAt.IsZero() && event.Timestamp.Before(process.StartedAt) {
			return // PID was not necessarily the same process when this event occurred.
		}
		if process.Executable == "" || event.Process.Image != process.Executable {
			return
		}
		event.Process.ProcessGUID = process.ProcessGUID
		event.Process.ParentProcessGUID = process.ParentProcessGUID
		event.Process.StartTimeTicks = process.StartTimeTicks
		event.Process.ContainerID = process.ContainerID
		if event.Process.ExecutableSHA256 == "" {
			event.Process.ExecutableSHA256 = process.ExecutableSHA256
		}
		return
	}
}

func (g *Graph) Stats() Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	stats := g.state.Stats
	stats.ActiveProcesses = len(g.state.Active)
	stats.ExitedProcesses = len(g.state.Exited)
	return stats
}

// Lookup returns a process only when both PID and start ticks match. Callers
// that only know a PID must not use it for attribution because PIDs are reused.
func (g *Graph) Lookup(pid int, startTicks uint64) (Process, bool) {
	if pid <= 0 || startTicks == 0 {
		return Process{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, process := range g.state.Active {
		if process.PID == pid && process.StartTimeTicks == startTicks {
			return process, true
		}
	}
	return Process{}, false
}

// LookupByBootTime resolves an eBPF task start timestamp without trusting a
// PID alone. Linux exposes /proc start time in clock ticks while CO-RE task
// telemetry uses nanoseconds since boot; a one-tick tolerance accounts for
// the intentional truncation in /proc. It never selects an ambiguous node.
func (g *Graph) LookupByBootTime(pid int, startBootTimeNS uint64) (Process, bool) {
	if pid <= 0 || startBootTimeNS == 0 {
		return Process{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.clockHz == 0 {
		return Process{}, false
	}
	expected := startBootTimeNS * g.clockHz / uint64(time.Second)
	var match Process
	found := false
	for _, process := range g.state.Active {
		if process.PID != pid || tickDistance(process.StartTimeTicks, expected) > 1 {
			continue
		}
		if found {
			return Process{}, false
		}
		match = process
		found = true
	}
	return match, found
}

// Snapshot reads one already-identified live process for a real-time sensor.
// It does not modify or checkpoint the graph. Callers must supply an exact
// PID/start-ticks pair and should cache the result rather than invoke it for
// high-volume file or network telemetry.
func (g *Graph) Snapshot(pid int, startTicks uint64) (Process, bool) {
	if pid <= 0 || startTicks == 0 {
		return Process{}, false
	}
	g.mu.Lock()
	options := g.options
	bootTime := g.bootTime
	clockHz := g.clockHz
	bootIDHash := g.state.BootIDHash
	g.mu.Unlock()
	if bootIDHash == "" {
		var err error
		bootIDHash, err = readBootIDHash(options.ProcRoot)
		if err != nil {
			return Process{}, false
		}
	}
	process, err := readProcess(options, pid, bootIDHash, bootTime, clockHz)
	if err != nil || process.StartTimeTicks != startTicks {
		return Process{}, false
	}
	return process, true
}

// SnapshotByBootTime is the bounded real-time equivalent of Snapshot for a
// CO-RE task start timestamp. It accepts only the same one-tick conversion
// tolerance as LookupByBootTime and does not alter graph state.
func (g *Graph) SnapshotByBootTime(pid int, startBootTimeNS uint64) (Process, bool) {
	if pid <= 0 || startBootTimeNS == 0 {
		return Process{}, false
	}
	g.mu.Lock()
	options := g.options
	bootTime := g.bootTime
	clockHz := g.clockHz
	bootIDHash := g.state.BootIDHash
	g.mu.Unlock()
	if clockHz == 0 {
		return Process{}, false
	}
	if bootIDHash == "" {
		var err error
		bootIDHash, err = readBootIDHash(options.ProcRoot)
		if err != nil {
			return Process{}, false
		}
	}
	process, err := readProcess(options, pid, bootIDHash, bootTime, clockHz)
	expected := startBootTimeNS * clockHz / uint64(time.Second)
	if err != nil || tickDistance(process.StartTimeTicks, expected) > 1 {
		return Process{}, false
	}
	return process, true
}

func tickDistance(left, right uint64) uint64 {
	if left > right {
		return left - right
	}
	return right - left
}

func ProcessGUID(bootIDHash string, pid int, startTicks uint64) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{"linux-process", bootIDHash, fmt.Sprintf("%d", pid), fmt.Sprintf("%d", startTicks)}, "\x00")))
	return "proc_" + hex.EncodeToString(digest[:])
}

func processStartEvent(process Process) model.Event {
	event := processEvent("process.start", process, "Linux process observed during /proc reconciliation")
	event.ID = eventID("start", process.ProcessGUID)
	event.Prepare()
	return event
}

func processExitEvent(process Process) model.Event {
	event := processEvent("process.exit", process, "Linux process exit inferred during /proc reconciliation")
	event.ID = eventID("exit", process.ProcessGUID)
	event.Prepare()
	return event
}

func processEvent(kind string, process Process, message string) model.Event {
	timestamp := process.ObservedAt
	if kind == "process.exit" && process.StoppedAt != nil {
		timestamp = *process.StoppedAt
	}
	return model.Event{
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  model.SeverityInfo,
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{OS: "linux"},
		Actor: model.Actor{
			User:      process.Username,
			AccountID: fmt.Sprintf("%d", process.UID),
			SessionID: process.Session,
		},
		Process: model.ProcessContext{
			PID:               process.PID,
			PPID:              process.PPID,
			Image:             process.Executable,
			CommandLine:       process.CommandLine,
			ExecutableSHA256:  process.ExecutableSHA256,
			ContainerID:       process.ContainerID,
			ProcessGUID:       process.ProcessGUID,
			ParentProcessGUID: process.ParentProcessGUID,
			StartTimeTicks:    process.StartTimeTicks,
		},
		Message: message,
		Attributes: map[string]interface{}{
			"process_graph": process,
		},
		Provenance: model.Provenance{Source: "local-host", Collector: "linux-proc-process-graph"},
	}
}

func eventID(action, guid string) string {
	digest := sha256.Sum256([]byte("linux-process-graph\x00" + action + "\x00" + guid))
	return "evt_" + hex.EncodeToString(digest[:])
}

func stopProcess(process Process, now time.Time, reason string) Process {
	process.StoppedAt = &now
	process.ExitReason = reason
	process.ObservedAt = now
	return process
}

func processMap(values []Process) map[string]Process {
	result := make(map[string]Process, len(values))
	for _, process := range values {
		if process.ProcessGUID != "" && process.StoppedAt == nil {
			result[process.ProcessGUID] = process
		}
	}
	return result
}

func sortedProcesses(values map[string]Process) []Process {
	result := make([]Process, 0, len(values))
	for _, process := range values {
		result = append(result, process)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].PID == result[j].PID {
			return result[i].ProcessGUID < result[j].ProcessGUID
		}
		return result[i].PID < result[j].PID
	})
	return result
}

func capExited(values []Process, maximum int) []Process {
	if maximum == 0 || len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool {
		left, right := values[i].StoppedAt, values[j].StoppedAt
		if left == nil || right == nil {
			return values[i].ProcessGUID < values[j].ProcessGUID
		}
		if left.Equal(*right) {
			return values[i].ProcessGUID < values[j].ProcessGUID
		}
		return left.Before(*right)
	})
	if len(values) > maximum {
		values = values[len(values)-maximum:]
	}
	return values
}

func cloneState(state persistedState) persistedState {
	result := state
	result.Active = append([]Process(nil), state.Active...)
	result.Exited = append([]Process(nil), state.Exited...)
	return result
}

func loadState(path string, options Options) (persistedState, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return persistedState{Version: stateVersion}, nil
	}
	if err != nil {
		return persistedState{}, fmt.Errorf("open process graph state: %w", err)
	}
	defer file.Close()
	content, err := readAllLimited(file, maxStateBytes)
	if err != nil {
		return persistedState{}, fmt.Errorf("read process graph state: %w", err)
	}
	state := persistedState{}
	if err := json.Unmarshal(content, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode process graph state: %w", err)
	}
	if state.Version != stateVersion {
		return persistedState{}, fmt.Errorf("unsupported process graph state version %d", state.Version)
	}
	if len(state.Active) > options.MaxProcesses || len(state.Exited) > options.MaxExitedProcesses {
		return persistedState{}, errors.New("process graph state exceeds configured bounds")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return persistedState{}, fmt.Errorf("secure process graph state: %w", err)
	}
	return state, nil
}

func saveState(path string, state persistedState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create process graph state directory: %w", err)
	}
	content, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode process graph state: %w", err)
	}
	if len(content) > maxStateBytes {
		return errors.New("process graph state exceeds 64 MiB")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".process-graph-*.tmp")
	if err != nil {
		return fmt.Errorf("create process graph state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure process graph state temporary file: %w", err)
	}
	if _, err := temporary.Write(content); err != nil {
		return fmt.Errorf("write process graph state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync process graph state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close process graph state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace process graph state: %w", err)
	}
	removeTemporary = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secure process graph state: %w", err)
	}
	return nil
}
