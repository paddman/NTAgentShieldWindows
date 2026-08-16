//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
)

const (
	minimumKernelMajor = 5
	minimumKernelMinor = 8
	maxRingBufferBytes = 64 * 1024 * 1024
	maxEventsPerSec    = 100000
	maxProcessCache    = 4096
)

//go:embed bpf/sensor_bpfel.o
var sensorObject []byte

const (
	eventExec uint16 = iota + 1
	eventExit
	eventTCPConnect
	eventTCPAccept
	eventFileOpen
	eventFileWrite
	eventFileRename
	eventFileUnlink
	eventFileChmod
	eventFileChown
	eventPtrace
	eventSetuid
	eventSetgid
	eventModuleLoad
	eventSetns
)

type wireEvent struct {
	TimestampNS        uint64
	CgroupID           uint64
	StartBootTimeNS    uint64
	PID                uint32
	TGID               uint32
	PPID               uint32
	UID                uint32
	GID                uint32
	Type               uint16
	Family             uint16
	Protocol           uint16
	OldState           uint16
	NewState           uint16
	SourcePort         uint16
	DestinationPort    uint16
	_                  uint16
	Result             int32
	Arg0               uint32
	Arg1               uint32
	Comm               [16]byte
	Path               [192]byte
	Path2              [192]byte
	SourceAddress      [16]byte
	DestinationAddress [16]byte
}

type hook struct {
	program string
	group   string
	name    string
}

var hooks = []hook{
	{"on_exec", "sched", "sched_process_exec"},
	{"on_exit", "sched", "sched_process_exit"},
	{"on_inet_state", "sock", "inet_sock_set_state"},
	{"on_openat", "syscalls", "sys_enter_openat"},
	{"on_open", "syscalls", "sys_enter_open"},
	{"on_write", "syscalls", "sys_enter_write"},
	{"on_renameat2", "syscalls", "sys_enter_renameat2"},
	{"on_unlinkat", "syscalls", "sys_enter_unlinkat"},
	{"on_chmod", "syscalls", "sys_enter_fchmodat"},
	{"on_chmod_direct", "syscalls", "sys_enter_chmod"},
	{"on_chown", "syscalls", "sys_enter_fchownat"},
	{"on_chown_direct", "syscalls", "sys_enter_chown"},
	{"on_ptrace", "syscalls", "sys_enter_ptrace"},
	{"on_setuid", "syscalls", "sys_enter_setuid"},
	{"on_setgid", "syscalls", "sys_enter_setgid"},
	{"on_module_load", "module", "module_load"},
	{"on_setns", "syscalls", "sys_enter_setns"},
}

type Sensor struct {
	mu         sync.Mutex
	graph      *processgraph.Graph
	options    Options
	collection *cebpf.Collection
	reader     *ringbuf.Reader
	links      []link.Link
	losses     *cebpf.Map
	health     Health
	cache      map[string]processgraph.Process
	cacheKeys  []string
	windowAt   time.Time
	windowN    uint64
	closed     bool
}

func New(graph *processgraph.Graph, options Options) (*Sensor, error) {
	if graph == nil {
		return nil, errors.New("eBPF sensor requires the Linux process graph")
	}
	if options.RingBufferBytes == 0 {
		options.RingBufferBytes = defaultRingBufferBytes
	}
	if options.MaxEventsPerSec == 0 {
		options.MaxEventsPerSec = defaultMaxEventsPerSec
	}
	if options.RingBufferBytes < 1<<20 || options.RingBufferBytes > maxRingBufferBytes || options.RingBufferBytes&(options.RingBufferBytes-1) != 0 {
		return nil, errors.New("eBPF ring buffer must be a power of two between 1 MiB and 64 MiB")
	}
	if options.MaxEventsPerSec < 100 || options.MaxEventsPerSec > maxEventsPerSec {
		return nil, errors.New("eBPF max events per second must be between 100 and 100000")
	}
	return &Sensor{graph: graph, options: options, cache: map[string]processgraph.Process{}}, nil
}

func CheckSupport() error {
	if runtime.GOOS != "linux" {
		return ErrUnsupported
	}
	major, minor, err := kernelVersion()
	if err != nil {
		return fmt.Errorf("read kernel version: %w", err)
	}
	if major < minimumKernelMajor || major == minimumKernelMajor && minor < minimumKernelMinor {
		return fmt.Errorf("%w: kernel %d.%d is older than 5.8 ring-buffer support", ErrUnsupported, major, minor)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("%w: kernel BTF is unavailable: %v", ErrUnsupported, err)
	}
	if _, err := btf.LoadKernelSpec(); err != nil {
		return fmt.Errorf("%w: load kernel BTF: %v", ErrUnsupported, err)
	}
	if !hasBPFCapabilities() {
		return fmt.Errorf("%w: CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN is required", ErrUnsupported)
	}
	return nil
}

func (s *Sensor) Start(ctx context.Context, sink EventSink) error {
	if sink == nil {
		return errors.New("eBPF sensor event sink is required")
	}
	if err := CheckSupport(); err != nil {
		s.setFallback(err)
		return err
	}
	s.mu.Lock()
	if s.collection != nil || s.closed {
		s.mu.Unlock()
		return errors.New("eBPF sensor is already started or closed")
	}
	s.mu.Unlock()
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(sensorObject))
	if err != nil {
		s.setFallback(fmt.Errorf("parse embedded CO-RE object: %w", err))
		return err
	}
	if spec.Maps["events"] == nil || spec.Maps["losses"] == nil {
		err := errors.New("embedded eBPF object is missing required maps")
		s.setFallback(err)
		return err
	}
	spec.Maps["events"].MaxEntries = uint32(s.options.RingBufferBytes)
	kernelTypes, err := btf.LoadKernelSpec()
	if err != nil {
		s.setFallback(fmt.Errorf("load kernel BTF: %w", err))
		return err
	}
	collection, err := cebpf.NewCollectionWithOptions(spec, cebpf.CollectionOptions{Programs: cebpf.ProgramOptions{KernelTypes: kernelTypes}})
	if err != nil {
		s.setFallback(fmt.Errorf("load CO-RE programs: %w", err))
		return err
	}
	attached := make([]link.Link, 0, len(hooks))
	for _, definition := range hooks {
		program := collection.Programs[definition.program]
		if program == nil {
			closeLinks(attached)
			collection.Close()
			return fmt.Errorf("embedded eBPF object is missing program %q", definition.program)
		}
		attachedLink, err := link.Tracepoint(definition.group, definition.name, program, nil)
		if err != nil {
			closeLinks(attached)
			collection.Close()
			s.setFallback(fmt.Errorf("attach %s/%s: %w", definition.group, definition.name, err))
			return err
		}
		attached = append(attached, attachedLink)
	}
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		closeLinks(attached)
		collection.Close()
		s.setFallback(fmt.Errorf("open ring buffer: %w", err))
		return err
	}
	s.mu.Lock()
	s.collection = collection
	s.reader = reader
	s.links = attached
	s.losses = collection.Maps["losses"]
	s.health = Health{Enabled: true, LoadedPrograms: len(hooks), AttachedHooks: len(attached)}
	s.windowAt = time.Now()
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	go s.run(ctx, sink)
	return nil
}

func (s *Sensor) run(ctx context.Context, sink EventSink) {
	s.mu.Lock()
	reader := s.reader
	s.mu.Unlock()
	if reader == nil {
		return
	}
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) || ctx.Err() != nil {
				return
			}
			s.recordParseError()
			continue
		}
		var raw wireEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			s.recordParseError()
			continue
		}
		event := s.normalize(raw)
		if isOperationalSelfEvent(event) {
			continue
		}
		if !s.allowEvent() {
			continue
		}
		if err := sink(event); err != nil {
			s.recordParseError()
		}
	}
}

func (s *Sensor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	reader := s.reader
	links := s.links
	collection := s.collection
	s.reader, s.links, s.collection = nil, nil, nil
	s.mu.Unlock()
	if reader != nil {
		_ = reader.Close()
	}
	closeLinks(links)
	if collection != nil {
		collection.Close()
	}
	return nil
}

func (s *Sensor) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	health := s.health
	if s.losses != nil {
		var values []uint64
		if err := s.losses.Lookup(uint32(0), &values); err == nil {
			for _, value := range values {
				health.RingBufferLoss += value
			}
		}
	}
	return health
}

func (s *Sensor) setFallback(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health.Enabled = false
	s.health.FallbackReason = boundedError(err)
}

func (s *Sensor) recordParseError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health.ParseErrors++
}

func (s *Sensor) allowEvent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.windowAt) >= time.Second {
		s.health.EventsPerSecond = s.windowN
		s.windowAt, s.windowN = now, 0
	}
	if s.windowN >= uint64(s.options.MaxEventsPerSec) {
		s.health.ThrottledEvents++
		return false
	}
	s.windowN++
	s.health.LastEventAt = now.UTC()
	return true
}

func (s *Sensor) normalize(raw wireEvent) model.Event {
	process := s.resolveProcess(raw)
	kind, message := kindFor(raw.Type)
	event := model.Event{
		ID:        eventID(raw),
		Timestamp: time.Now().UTC(),
		Kind:      kind,
		Severity:  model.SeverityInfo,
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{OS: "linux"},
		Actor:     model.Actor{User: strconv.FormatUint(uint64(raw.UID), 10)},
		Process:   process,
		Message:   message,
		Attributes: map[string]interface{}{
			"ebpf": map[string]interface{}{
				"monotonic_timestamp_ns": raw.TimestampNS,
				"cgroup_id":              strconv.FormatUint(raw.CgroupID, 10),
				"start_boottime_ns":      raw.StartBootTimeNS,
				"uid":                    raw.UID,
				"gid":                    raw.GID,
				"ppid":                   raw.PPID,
				"arg0":                   raw.Arg0,
				"arg1":                   raw.Arg1,
				"path":                   cString(raw.Path[:]),
				"path2":                  cString(raw.Path2[:]),
			},
		},
		Provenance: model.Provenance{Source: "local-host", Collector: "linux-ebpf-core"},
	}
	if raw.Type == eventTCPConnect || raw.Type == eventTCPAccept {
		event.Network = model.NetworkContext{SourceIP: ipString(raw.SourceAddress, raw.Family), SourcePort: int(raw.SourcePort), DestinationIP: ipString(raw.DestinationAddress, raw.Family), DestinationPort: int(raw.DestinationPort), Protocol: "tcp", Direction: map[bool]string{true: "inbound", false: "outbound"}[raw.Type == eventTCPAccept]}
		event.Attributes["ebpf"].(map[string]interface{})["socket_state"] = map[string]uint16{"old": raw.OldState, "new": raw.NewState}
	}
	event.Prepare()
	return event
}

func (s *Sensor) resolveProcess(raw wireEvent) model.ProcessContext {
	context := model.ProcessContext{PID: int(raw.TGID), PPID: int(raw.PPID), Image: cString(raw.Comm[:])}
	if raw.Type == eventExec && cString(raw.Path[:]) != "" {
		context.Image = cString(raw.Path[:])
	}
	if s.graph == nil {
		return context
	}
	process := processgraph.Process{}
	key := fmt.Sprintf("%d:%d", raw.TGID, raw.StartBootTimeNS)
	s.mu.Lock()
	process, cached := s.cache[key]
	s.mu.Unlock()
	if !cached {
		process, cached = s.graph.LookupByBootTime(int(raw.TGID), raw.StartBootTimeNS)
		if !cached && raw.Type == eventExec {
			process, cached = s.graph.SnapshotByBootTime(int(raw.TGID), raw.StartBootTimeNS)
		}
		if cached {
			s.cacheProcess(key, process)
		}
	}
	if !cached {
		return context
	}
	context.PID = process.PID
	context.PPID = process.PPID
	context.Image = process.Executable
	context.CommandLine = process.CommandLine
	context.ProcessGUID = process.ProcessGUID
	context.ParentProcessGUID = process.ParentProcessGUID
	context.StartTimeTicks = process.StartTimeTicks
	context.ExecutableSHA256 = process.ExecutableSHA256
	context.ContainerID = process.ContainerID
	return context
}

func (s *Sensor) cacheProcess(key string, process processgraph.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.cache[key]; exists {
		return
	}
	if len(s.cacheKeys) >= maxProcessCache {
		delete(s.cache, s.cacheKeys[0])
		s.cacheKeys = s.cacheKeys[1:]
	}
	s.cache[key] = process
	s.cacheKeys = append(s.cacheKeys, key)
}

var eventDefinitions = map[uint16]struct{ kind, message string }{
	eventExec:       {"process.exec", "Linux process execution observed by eBPF"},
	eventExit:       {"process.exit", "Linux process exit observed by eBPF"},
	eventTCPConnect: {"network.connect", "Linux TCP connection observed by eBPF"},
	eventTCPAccept:  {"network.accept", "Linux TCP accept observed by eBPF"},
	eventFileOpen:   {"file.open", "Linux file open observed by eBPF"},
	eventFileWrite:  {"file.write", "Linux file write observed by eBPF"},
	eventFileRename: {"file.rename", "Linux file rename observed by eBPF"},
	eventFileUnlink: {"file.unlink", "Linux file unlink observed by eBPF"},
	eventFileChmod:  {"file.chmod", "Linux chmod observed by eBPF"},
	eventFileChown:  {"file.chown", "Linux chown observed by eBPF"},
	eventPtrace:     {"process.ptrace", "Linux ptrace observed by eBPF"},
	eventSetuid:     {"identity.setuid", "Linux setuid observed by eBPF"},
	eventSetgid:     {"identity.setgid", "Linux setgid observed by eBPF"},
	eventModuleLoad: {"kernel.module_load", "Linux kernel module load observed by eBPF"},
	eventSetns:      {"process.namespace_change", "Linux namespace change observed by eBPF"},
}

func kindFor(eventType uint16) (string, string) {
	definition, exists := eventDefinitions[eventType]
	if !exists {
		return "sensor.unknown", "Unknown Linux eBPF event"
	}
	return definition.kind, definition.message
}

func eventID(raw wireEvent) string {
	encoded := make([]byte, 0, 64+len(raw.Path)+len(raw.Path2))
	for _, value := range []uint64{raw.TimestampNS, raw.CgroupID, raw.StartBootTimeNS} {
		encoded = binary.LittleEndian.AppendUint64(encoded, value)
	}
	for _, value := range []uint32{raw.PID, raw.TGID, raw.PPID, raw.UID, raw.GID, raw.Arg0, raw.Arg1} {
		encoded = binary.LittleEndian.AppendUint32(encoded, value)
	}
	encoded = binary.LittleEndian.AppendUint16(encoded, raw.Type)
	encoded = append(encoded, raw.Path[:]...)
	encoded = append(encoded, raw.Path2[:]...)
	digest := sha256.Sum256(append([]byte("linux-ebpf-core\x00"), encoded...))
	return "evt_" + hex.EncodeToString(digest[:])
}

func ipString(value [16]byte, family uint16) string {
	if family == unix.AF_INET {
		return net.IP(value[:4]).String()
	}
	if family == unix.AF_INET6 {
		return net.IP(value[:]).String()
	}
	return ""
}

func cString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(string(value))
}

func closeLinks(links []link.Link) {
	for index := len(links) - 1; index >= 0; index-- {
		_ = links[index].Close()
	}
}

func kernelVersion() (int, int, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return 0, 0, err
	}
	release := charsToString(uname.Release[:])
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid kernel release %q", release)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	minor, err := strconv.Atoi(parts[1])
	return major, minor, err
}

func charsToString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}

func hasBPFCapabilities() bool {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}
	if unix.Capget(&header, &data[0]) != nil {
		return false
	}
	return hasBPFEffectiveCapabilities(data)
}

func hasBPFEffectiveCapabilities(data [2]unix.CapUserData) bool {
	has := func(capability uint) bool {
		return data[capability/32].Effective&(uint32(1)<<(capability%32)) != 0
	}
	return has(unix.CAP_SYS_ADMIN) || has(unix.CAP_BPF) && has(unix.CAP_PERFMON)
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(value) > 240 {
		return value[:240]
	}
	return value
}
