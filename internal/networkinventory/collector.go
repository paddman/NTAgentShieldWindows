// Package networkinventory builds bounded, process-aware Linux socket
// inventory from fixed /proc files. It is evidence-only and has no command or
// response capability.
package networkinventory

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
)

const (
	defaultMaxProcesses   = 4096
	defaultMaxSockets     = 8192
	defaultMaxFDs         = 65536
	maxWarnings           = 32
	processDirectorySlack = 1024
	directoryReadBatch    = 256
	maxSocketLineFactor   = 2
)

type Options struct {
	ProcRoot     string
	MaxProcesses int
	MaxSockets   int
	MaxFDs       int
}

type Socket struct {
	ProcessGUID string `json:"process_guid"`
	PID         int    `json:"pid"`
	Executable  string `json:"executable,omitempty"`
	User        string `json:"user,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Cgroup      string `json:"cgroup,omitempty"`
	Inode       string `json:"socket_inode"`
	LocalIP     string `json:"local_ip"`
	LocalPort   int    `json:"local_port"`
	RemoteIP    string `json:"remote_ip,omitempty"`
	RemotePort  int    `json:"remote_port,omitempty"`
	Protocol    string `json:"protocol"`
	State       string `json:"socket_state"`
	Listening   bool   `json:"listening"`
}

type Stats struct {
	KnownSockets int       `json:"known_sockets"`
	Scans        uint64    `json:"scans"`
	NewSockets   uint64    `json:"new_sockets"`
	Warnings     uint64    `json:"warnings"`
	LastScan     time.Time `json:"last_scan,omitempty"`
}

type Collector struct {
	mu      sync.Mutex
	options Options
	graph   *processgraph.Graph
	known   map[string]struct{}
	pending *pendingBatch
	stats   Stats
}

type pendingBatch struct {
	known  map[string]struct{}
	events []model.Event
	stats  Stats
}

type Batch struct {
	Events    []model.Event
	collector *Collector
	pending   *pendingBatch
}

func New(graph *processgraph.Graph, options Options) (*Collector, error) {
	if graph == nil {
		return nil, errors.New("process graph is required for network attribution")
	}
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	return &Collector{options: options, graph: graph, known: map[string]struct{}{}}, nil
}

func normalizeOptions(options Options) Options {
	if options.ProcRoot == "" {
		options.ProcRoot = "/proc"
	}
	options.ProcRoot = filepath.Clean(options.ProcRoot)
	if options.MaxProcesses == 0 {
		options.MaxProcesses = defaultMaxProcesses
	}
	if options.MaxSockets == 0 {
		options.MaxSockets = defaultMaxSockets
	}
	if options.MaxFDs == 0 {
		options.MaxFDs = defaultMaxFDs
	}
	return options
}

func validateOptions(options Options) error {
	if options.MaxProcesses < 1 || options.MaxProcesses > 16384 {
		return errors.New("network inventory max processes must be between 1 and 16384")
	}
	if options.MaxSockets < 1 || options.MaxSockets > 32768 {
		return errors.New("network inventory max sockets must be between 1 and 32768")
	}
	if options.MaxFDs < 1 || options.MaxFDs > 262144 {
		return errors.New("network inventory max file descriptors must be between 1 and 262144")
	}
	return nil
}

func (c *Collector) Reconcile(ctx context.Context) (Batch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != nil {
		return Batch{Events: append([]model.Event(nil), c.pending.events...), collector: c, pending: c.pending}, nil
	}
	sockets, warnings, err := scan(ctx, c.graph, c.options)
	if err != nil {
		c.stats.Warnings++
		return Batch{}, err
	}
	now := time.Now().UTC()
	nextKnown := make(map[string]struct{}, len(sockets))
	events := make([]model.Event, 0)
	for _, socket := range sockets {
		key := socketKey(socket)
		nextKnown[key] = struct{}{}
		if _, exists := c.known[key]; exists {
			continue
		}
		events = append(events, socketEvent(socket, now))
	}
	nextStats := c.stats
	nextStats.Scans++
	nextStats.NewSockets += uint64(len(events))
	nextStats.Warnings += uint64(len(warnings))
	nextStats.LastScan = now
	nextStats.KnownSockets = len(nextKnown)
	pending := &pendingBatch{known: nextKnown, events: events, stats: nextStats}
	c.pending = pending
	return Batch{Events: append([]model.Event(nil), events...), collector: c, pending: pending}, nil
}

func (b Batch) Acknowledge() error {
	if b.collector == nil || b.pending == nil {
		return nil
	}
	b.collector.mu.Lock()
	defer b.collector.mu.Unlock()
	if b.collector.pending != b.pending {
		return nil
	}
	b.collector.known = b.pending.known
	b.collector.stats = b.pending.stats
	b.collector.pending = nil
	return nil
}

func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	stats := c.stats
	stats.KnownSockets = len(c.known)
	return stats
}

type socketSource struct {
	path     string
	protocol string
	ipv6     bool
	tcp      bool
}

func scan(ctx context.Context, graph *processgraph.Graph, options Options) ([]Socket, []string, error) {
	sourceSockets := map[string]socketMetadata{}
	warnings := make([]string, 0)
	sources := []socketSource{
		{path: filepath.Join(options.ProcRoot, "net", "tcp"), protocol: "tcp", tcp: true},
		{path: filepath.Join(options.ProcRoot, "net", "tcp6"), protocol: "tcp6", ipv6: true, tcp: true},
		{path: filepath.Join(options.ProcRoot, "net", "udp"), protocol: "udp"},
		{path: filepath.Join(options.ProcRoot, "net", "udp6"), protocol: "udp6", ipv6: true},
	}
	for index, source := range sources {
		remaining := options.MaxSockets - len(sourceSockets)
		if remaining <= 0 {
			appendWarning(&warnings, "socket scan reached configured maximum")
			break
		}
		sourceLimit := remaining / (len(sources) - index)
		if sourceLimit < 1 {
			sourceLimit = 1
		}
		parsed, capped, err := parseSocketFile(source, sourceLimit)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			appendWarning(&warnings, source.path+": "+boundedError(err))
			continue
		}
		if capped {
			appendWarning(&warnings, source.path+": socket table reached configured maximum")
		}
		for inode, socket := range parsed {
			sourceSockets[inode] = socket
		}
	}
	pids, capped, err := readProcessIDs(options.ProcRoot, options.MaxProcesses)
	if err != nil {
		return nil, warnings, fmt.Errorf("read proc root: %w", err)
	}
	if capped {
		appendWarning(&warnings, "process attribution scan reached configured maximum")
	}
	result := make([]Socket, 0)
	seen := map[string]struct{}{}
	fdCount := 0
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return result, warnings, err
		}
		if fdCount >= options.MaxFDs || len(result) >= options.MaxSockets {
			appendWarning(&warnings, "file descriptor attribution scan reached configured maximum")
			break
		}
		startTicks, err := processgraph.StartTimeTicks(options.ProcRoot, pid)
		if err != nil {
			if !os.IsNotExist(err) {
				appendWarning(&warnings, fmt.Sprintf("pid %d stat: %s", pid, boundedError(err)))
			}
			continue
		}
		process, exists := graph.Lookup(pid, startTicks)
		if !exists {
			continue // Reconciliation has not observed this identity or PID was reused.
		}
		user := process.Username
		if user == "" {
			user = strconv.FormatUint(uint64(process.UID), 10)
		}
		fds, capped, err := readDirectoryEntries(filepath.Join(options.ProcRoot, strconv.Itoa(pid), "fd"), options.MaxFDs-fdCount)
		if err != nil {
			if !os.IsNotExist(err) {
				appendWarning(&warnings, fmt.Sprintf("pid %d fd: %s", pid, boundedError(err)))
			}
			continue
		}
		if capped {
			appendWarning(&warnings, "file descriptor attribution scan reached configured maximum")
		}
		processSockets := make([]Socket, 0)
		processSeen := map[string]struct{}{}
		for _, fd := range fds {
			if len(result) >= options.MaxSockets {
				appendWarning(&warnings, "file descriptor attribution scan reached configured maximum")
				break
			}
			fdCount++
			target, err := os.Readlink(filepath.Join(options.ProcRoot, strconv.Itoa(pid), "fd", fd.Name()))
			if err != nil {
				continue // File descriptors disappear while processes exit.
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			metadata, exists := sourceSockets[inode]
			if !exists {
				continue
			}
			socket := Socket{
				ProcessGUID: process.ProcessGUID,
				PID:         process.PID,
				Executable:  process.Executable,
				User:        user,
				ContainerID: process.ContainerID,
				Cgroup:      process.Cgroup,
				Inode:       inode,
				LocalIP:     metadata.localIP,
				LocalPort:   metadata.localPort,
				RemoteIP:    metadata.remoteIP,
				RemotePort:  metadata.remotePort,
				Protocol:    metadata.protocol,
				State:       metadata.state,
				Listening:   metadata.listening,
			}
			key := socketKey(socket)
			if _, duplicate := processSeen[key]; duplicate {
				continue
			}
			processSeen[key] = struct{}{}
			processSockets = append(processSockets, socket)
		}
		currentTicks, err := processgraph.StartTimeTicks(options.ProcRoot, pid)
		if err != nil || currentTicks != startTicks {
			// PID reuse can race with /proc traversal. Do not attribute the
			// descriptors collected above unless the identity is still current.
			continue
		}
		for _, socket := range processSockets {
			if len(result) >= options.MaxSockets {
				appendWarning(&warnings, "file descriptor attribution scan reached configured maximum")
				break
			}
			key := socketKey(socket)
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, socket)
		}
	}
	sort.Slice(result, func(i, j int) bool { return socketKey(result[i]) < socketKey(result[j]) })
	return result, warnings, nil
}

type socketMetadata struct {
	localIP, remoteIP     string
	localPort, remotePort int
	protocol, state       string
	listening             bool
}

func readProcessIDs(procRoot string, maxProcesses int) ([]int, bool, error) {
	entries, capped, err := readDirectoryEntries(procRoot, maxProcesses+processDirectorySlack)
	if err != nil {
		return nil, false, err
	}
	pids := make([]int, 0, maxProcesses)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		pids = append(pids, pid)
		if len(pids) == maxProcesses {
			return sortedPIDs(pids), true, nil
		}
	}
	return sortedPIDs(pids), capped, nil
}

func readDirectoryEntries(path string, maxEntries int) ([]os.DirEntry, bool, error) {
	if maxEntries < 1 {
		return nil, true, nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	entries := make([]os.DirEntry, 0, maxEntries)
	for len(entries) < maxEntries {
		count := directoryReadBatch
		if remaining := maxEntries - len(entries); remaining < count {
			count = remaining
		}
		batch, readErr := directory.ReadDir(count)
		entries = append(entries, batch...)
		if readErr == io.EOF {
			return entries, false, nil
		}
		if readErr != nil {
			return nil, false, readErr
		}
	}
	return entries, true, nil
}

func sortedPIDs(pids []int) []int {
	sort.Ints(pids)
	return pids
}

func parseSocketFile(source socketSource, maxSockets int) (map[string]socketMetadata, bool, error) {
	file, err := os.Open(source.path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	result := map[string]socketMetadata{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	line := 0
	maxLines := maxSockets * maxSocketLineFactor
	for scanner.Scan() {
		line++
		if line == 1 {
			continue
		}
		if line-1 > maxLines {
			return result, true, nil
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		localIP, localPort, err := parseProcAddress(fields[1], source.ipv6)
		if err != nil {
			continue
		}
		remoteIP, remotePort, err := parseProcAddress(fields[2], source.ipv6)
		if err != nil {
			continue
		}
		inode := fields[9]
		if _, err := strconv.ParseUint(inode, 10, 64); err != nil {
			continue
		}
		state := socketState(source.tcp, fields[3])
		result[inode] = socketMetadata{localIP: localIP, localPort: localPort, remoteIP: remoteIP, remotePort: remotePort, protocol: source.protocol, state: state, listening: source.tcp && fields[3] == "0A"}
		if len(result) >= maxSockets {
			return result, true, nil
		}
	}
	return result, false, scanner.Err()
}

func parseProcAddress(value string, ipv6 bool) (string, int, error) {
	address, portText, found := strings.Cut(value, ":")
	if !found {
		return "", 0, errors.New("invalid proc socket address")
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return "", 0, err
	}
	decoded, err := hex.DecodeString(address)
	if err != nil {
		return "", 0, err
	}
	if ipv6 {
		if len(decoded) != net.IPv6len {
			return "", 0, errors.New("invalid proc IPv6 address")
		}
		for index := 0; index < len(decoded); index += 4 {
			decoded[index], decoded[index+3] = decoded[index+3], decoded[index]
			decoded[index+1], decoded[index+2] = decoded[index+2], decoded[index+1]
		}
	} else {
		if len(decoded) != net.IPv4len {
			return "", 0, errors.New("invalid proc IPv4 address")
		}
		for left, right := 0, len(decoded)-1; left < right; left, right = left+1, right-1 {
			decoded[left], decoded[right] = decoded[right], decoded[left]
		}
	}
	return net.IP(decoded).String(), int(port), nil
}

func socketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if inode == "" {
		return "", false
	}
	if _, err := strconv.ParseUint(inode, 10, 64); err != nil {
		return "", false
	}
	return inode, true
}

func socketState(tcp bool, value string) string {
	if !tcp {
		if value == "07" {
			return "UNCONN"
		}
		return value
	}
	if mapped := map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}[value]; mapped != "" {
		return mapped
	}
	return value
}

func socketKey(socket Socket) string {
	return strings.Join([]string{socket.ProcessGUID, socket.Inode, socket.Protocol, socket.LocalIP, strconv.Itoa(socket.LocalPort), socket.RemoteIP, strconv.Itoa(socket.RemotePort), socket.State}, "\x00")
}

func socketEvent(socket Socket, timestamp time.Time) model.Event {
	kind := "network.connection"
	direction := "unknown"
	if socket.Listening {
		kind = "network.listen"
		direction = "listen"
	}
	digest := sha256.Sum256([]byte("linux-network-inventory\x00" + socketKey(socket)))
	event := model.Event{
		ID:        "evt_" + hex.EncodeToString(digest[:]),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  model.SeverityInfo,
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{OS: "linux"},
		Actor:     model.Actor{User: socket.User},
		Process: model.ProcessContext{
			PID:         socket.PID,
			ProcessGUID: socket.ProcessGUID,
			Image:       socket.Executable,
			ContainerID: socket.ContainerID,
		},
		Network: model.NetworkContext{
			SourceIP:        socket.LocalIP,
			SourcePort:      socket.LocalPort,
			DestinationIP:   socket.RemoteIP,
			DestinationPort: socket.RemotePort,
			Protocol:        socket.Protocol,
			Direction:       direction,
		},
		Message: "Linux process-aware socket observed during /proc inventory",
		Attributes: map[string]interface{}{
			"network_inventory": socket,
		},
		Provenance: model.Provenance{Source: "local-host", Collector: "linux-proc-network-inventory"},
	}
	event.Prepare()
	return event
}

func appendWarning(warnings *[]string, value string) {
	if len(*warnings) < maxWarnings {
		*warnings = append(*warnings, value)
	}
}

func boundedError(err error) string {
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
