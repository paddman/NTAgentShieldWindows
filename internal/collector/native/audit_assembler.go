package native

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

// AuditAssemblerOptions bounds all in-memory state retained while related
// audit records wait for the remainder of their serial group. The collector
// treats audit records as untrusted evidence; these options never influence
// policy, tools, or response behavior.
type AuditAssemblerOptions struct {
	MaxActiveSerials    int
	MaxRecordsPerSerial int
	MaxBytesPerSerial   int
	AssemblyTimeout     time.Duration
}

type AuditAssemblyStats struct {
	ActiveSerials        int    `json:"active_serials"`
	AssembledEvents      uint64 `json:"assembled_events"`
	IncompleteAssemblies uint64 `json:"incomplete_assemblies"`
	DroppedRecords       uint64 `json:"dropped_records"`
}

type auditRecord struct {
	TypeName  string
	Serial    string
	Timestamp time.Time
	Fields    map[string]string
	Hash      string
	Bytes     int
}

type auditAssembly struct {
	serial        string
	firstSeen     time.Time
	lastSeen      time.Time
	records       []auditRecord
	bytes         int
	finalized     bool
	delivered     bool
	partial       bool
	partialReason string
	endSeen       bool
}

type auditRecordSlot struct {
	endOffset int64
	assembly  *auditAssembly
	safe      bool
}

type auditAssembler struct {
	mu      sync.Mutex
	options AuditAssemblerOptions
	active  map[string]*auditAssembly
	slots   []auditRecordSlot
	stats   AuditAssemblyStats
}

func newAuditAssembler(options AuditAssemblerOptions) (*auditAssembler, error) {
	if options.MaxActiveSerials < 1 || options.MaxRecordsPerSerial < 1 || options.MaxBytesPerSerial < 4096 || options.AssemblyTimeout < 100*time.Millisecond {
		return nil, fmt.Errorf("invalid audit assembler options")
	}
	return &auditAssembler{options: options, active: map[string]*auditAssembly{}}, nil
}

func parseAuditRecord(line string) (auditRecord, error) {
	fields := parseAuditFields(line)
	// Parse the kernel audit envelope from the complete record. USER_CMD and
	// several authentication records can contain a second msg= field whose
	// application payload legitimately overwrites fields["msg"]. That payload
	// must never be allowed to hide the serial used for assembly and cursor
	// ordering.
	timestamp, serial := auditTimestamp(line)
	if serial == "" || serial == "unknown" {
		return auditRecord{}, fmt.Errorf("audit record has no serial")
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(line)))
	return auditRecord{
		TypeName:  strings.ToUpper(strings.TrimSpace(fields["type"])),
		Serial:    serial,
		Timestamp: timestamp,
		Fields:    fields,
		Hash:      hex.EncodeToString(digest[:]),
		Bytes:     len(line),
	}, nil
}

func (a *auditAssembler) Add(record auditRecord, endOffset int64, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.add(record, endOffset, now.UTC())
}

func (a *auditAssembler) add(record auditRecord, endOffset int64, now time.Time) {
	assembly := a.active[record.Serial]
	if assembly == nil {
		if len(a.active) >= a.options.MaxActiveSerials {
			a.finalize(a.oldestActive(), "max_active_serials")
		}
		assembly = &auditAssembly{serial: record.Serial, firstSeen: now, lastSeen: now}
		a.active[record.Serial] = assembly
	}
	if len(assembly.records) >= a.options.MaxRecordsPerSerial {
		a.finalize(assembly, "max_records_per_serial")
		assembly = &auditAssembly{serial: record.Serial, firstSeen: now, lastSeen: now}
		a.active[record.Serial] = assembly
	}
	if assembly.bytes > 0 && assembly.bytes+record.Bytes > a.options.MaxBytesPerSerial {
		a.finalize(assembly, "max_bytes_per_serial")
		assembly = &auditAssembly{serial: record.Serial, firstSeen: now, lastSeen: now}
		a.active[record.Serial] = assembly
	}
	if record.Bytes > a.options.MaxBytesPerSerial {
		// Retain only the record hash and bounded parsed metadata as a partial
		// evidence event. Raw content is deliberately not kept beyond the cap.
		a.stats.DroppedRecords++
		record.Fields = map[string]string{"type": record.TypeName}
		record.Bytes = 0
		assembly.partial = true
		assembly.partialReason = "record_exceeds_max_bytes_per_serial"
	}
	assembly.records = append(assembly.records, record)
	assembly.bytes += record.Bytes
	assembly.lastSeen = now
	if record.TypeName == "EOE" {
		assembly.endSeen = true
	}
	a.slots = append(a.slots, auditRecordSlot{endOffset: endOffset, assembly: assembly})
	if assembly.partial && assembly.partialReason == "record_exceeds_max_bytes_per_serial" {
		a.finalize(assembly, assembly.partialReason)
	}
}

func (a *auditAssembler) Advance(endOffset int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.slots = append(a.slots, auditRecordSlot{endOffset: endOffset, safe: true})
}

func (a *auditAssembler) Skip(endOffset int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.DroppedRecords++
	a.slots = append(a.slots, auditRecordSlot{endOffset: endOffset, safe: true})
}

func (a *auditAssembler) FlushExpired(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := now.UTC().Add(-a.options.AssemblyTimeout)
	for _, assembly := range a.active {
		if !assembly.lastSeen.After(cutoff) {
			reason := "assembly_timeout"
			if assembly.endSeen {
				reason = ""
			}
			a.finalize(assembly, reason)
		}
	}
}

func (a *auditAssembler) FlushAll(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	serials := make([]string, 0, len(a.active))
	for serial := range a.active {
		serials = append(serials, serial)
	}
	sort.Strings(serials)
	for _, serial := range serials {
		assembly := a.active[serial]
		if assembly.endSeen {
			a.finalize(assembly, "")
			continue
		}
		a.finalize(assembly, reason)
	}
}

func (a *auditAssembler) Ready(limit int, sourceID, path string) ([]model.Event, []*auditAssembly) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if limit < 1 {
		return nil, nil
	}
	ready := make([]*auditAssembly, 0)
	seen := map[*auditAssembly]struct{}{}
	for _, slot := range a.slots {
		assembly := slot.assembly
		if assembly == nil || !assembly.finalized || assembly.delivered {
			continue
		}
		if _, exists := seen[assembly]; exists {
			continue
		}
		ready = append(ready, assembly)
		seen[assembly] = struct{}{}
		if len(ready) == limit {
			break
		}
	}
	events := make([]model.Event, 0, len(ready))
	for _, assembly := range ready {
		events = append(events, assembly.event(sourceID, path))
	}
	return events, ready
}

func (a *auditAssembler) PreviewOffset(current int64, delivered []*auditAssembly) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	willDeliver := make(map[*auditAssembly]struct{}, len(delivered))
	for _, assembly := range delivered {
		willDeliver[assembly] = struct{}{}
	}
	offset := current
	for _, slot := range a.slots {
		if slot.safe || (slot.assembly != nil && slot.assembly.finalized && (slot.assembly.delivered || containsAssembly(willDeliver, slot.assembly))) {
			offset = slot.endOffset
			continue
		}
		break
	}
	return offset
}

func (a *auditAssembler) Acknowledge(delivered []*auditAssembly) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, assembly := range delivered {
		if assembly != nil && assembly.finalized {
			assembly.delivered = true
			// The event was durably journaled before the batch acknowledgement.
			// Only its cursor ordering marker remains necessary afterwards.
			assembly.records = nil
		}
	}
	a.compactAcknowledgedSlots()
	for len(a.slots) > 0 {
		slot := a.slots[0]
		if !slot.safe && (slot.assembly == nil || !slot.assembly.finalized || !slot.assembly.delivered) {
			break
		}
		a.slots = a.slots[1:]
	}
}

// compactAcknowledgedSlots retains at most one safe cursor watermark between
// undelivered groups. This prevents a long-lived earlier serial from keeping
// already-journaled record payloads or an unbounded number of slot entries.
// It is called only after the durable cursor commit succeeds.
func (a *auditAssembler) compactAcknowledgedSlots() {
	compacted := a.slots[:0]
	for index := 0; index < len(a.slots); {
		slot := a.slots[index]
		if !slot.safe && (slot.assembly == nil || !slot.assembly.finalized || !slot.assembly.delivered) {
			compacted = append(compacted, slot)
			index++
			continue
		}
		endOffset := slot.endOffset
		index++
		for index < len(a.slots) {
			next := a.slots[index]
			if !next.safe && (next.assembly == nil || !next.assembly.finalized || !next.assembly.delivered) {
				break
			}
			endOffset = next.endOffset
			index++
		}
		compacted = append(compacted, auditRecordSlot{endOffset: endOffset, safe: true})
	}
	a.slots = compacted
}

func (a *auditAssembler) EmptyAfter(delivered []*auditAssembly) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	willDeliver := make(map[*auditAssembly]struct{}, len(delivered))
	for _, assembly := range delivered {
		willDeliver[assembly] = struct{}{}
	}
	for _, slot := range a.slots {
		if slot.safe || (slot.assembly != nil && slot.assembly.finalized && (slot.assembly.delivered || containsAssembly(willDeliver, slot.assembly))) {
			continue
		}
		return false
	}
	return true
}

func (a *auditAssembler) Stats() AuditAssemblyStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	stats := a.stats
	stats.ActiveSerials = len(a.active)
	return stats
}

func (a *auditAssembler) oldestActive() *auditAssembly {
	var selected *auditAssembly
	for _, candidate := range a.active {
		if selected == nil || candidate.firstSeen.Before(selected.firstSeen) || (candidate.firstSeen.Equal(selected.firstSeen) && candidate.serial < selected.serial) {
			selected = candidate
		}
	}
	return selected
}

func (a *auditAssembler) finalize(assembly *auditAssembly, reason string) {
	if assembly == nil || assembly.finalized {
		return
	}
	assembly.finalized = true
	assembly.partial = reason != ""
	assembly.partialReason = reason
	if current := a.active[assembly.serial]; current == assembly {
		delete(a.active, assembly.serial)
	}
	a.stats.AssembledEvents++
	if assembly.partial {
		a.stats.IncompleteAssemblies++
	}
}

func containsAssembly(values map[*auditAssembly]struct{}, target *auditAssembly) bool {
	_, exists := values[target]
	return exists
}

func (assembly *auditAssembly) event(sourceID, path string) model.Event {
	records := append([]auditRecord(nil), assembly.records...)
	sort.Slice(records, func(i, j int) bool {
		if records[i].TypeName != records[j].TypeName {
			return records[i].TypeName < records[j].TypeName
		}
		return records[i].Hash < records[j].Hash
	})
	hashes := make([]string, 0, len(records))
	types := make([]string, 0, len(records))
	seenTypes := map[string]struct{}{}
	for _, record := range records {
		hashes = append(hashes, record.Hash)
		if _, exists := seenTypes[record.TypeName]; !exists {
			types = append(types, record.TypeName)
			seenTypes[record.TypeName] = struct{}{}
		}
	}
	sort.Strings(hashes)
	sort.Strings(types)
	timestamp := assemblyTimestamp(records)
	kind := auditGroupKind(records)
	commandLine := auditGroupCommandLine(records)
	paths := auditGroupPaths(records)
	fields := auditGroupFields(records)
	socket := auditGroupSocket(records)
	identity := map[string]string{}
	for _, key := range []string{"uid", "euid", "suid", "fsuid", "gid", "egid", "auid", "ses"} {
		if value := fields[key]; value != "" {
			identity[key] = value
		}
	}
	selinux := map[string]string{}
	for _, key := range []string{"subj", "scontext", "tcontext", "obj", "tclass", "perms"} {
		if value := fields[key]; value != "" {
			selinux[key] = value
		}
	}
	auditAttributes := map[string]interface{}{
		"serial":            assembly.serial,
		"timestamp":         timestamp.Format(time.RFC3339Nano),
		"record_types":      types,
		"raw_record_sha256": hashes,
		"raw_record_count":  len(records),
		"partial":           assembly.partial,
		"syscall":           fields["syscall"],
		"success":           auditSuccessValue(fields),
		"exit_code":         auditExitValue(fields),
		"identity":          identity,
		"cwd":               fields["cwd"],
		"affected_paths":    paths,
		"socket_address":    socket,
		"selinux_context":   selinux,
		"record_summaries":  auditRecordSummaries(records),
	}
	if assembly.partial {
		auditAttributes["partial_reason"] = assembly.partialReason
	}
	event := model.Event{
		ID:        deterministicEventID("auditd-assembly", sourceID, assembly.serial, strings.Join(hashes, ",")),
		Timestamp: timestamp,
		Kind:      kind,
		Severity:  auditGroupSeverity(records),
		Trust:     model.TrustUntrustedTelemetry,
		Asset:     model.Asset{OS: "linux"},
		Actor: model.Actor{
			User:      firstNonEmpty(fields["acct"], fields["uid"], fields["auid"]),
			AccountID: firstNonEmpty(fields["auid"], fields["ses"]),
			SessionID: fields["ses"],
		},
		Process: model.ProcessContext{
			PID:         flexibleInt(fields["pid"]),
			PPID:        flexibleInt(fields["ppid"]),
			Image:       firstNonEmpty(fields["exe"], fields["comm"]),
			CommandLine: commandLine,
		},
		Network: model.NetworkContext{
			SourceIP:   firstNonEmpty(fields["addr"], fields["hostname"]),
			SourcePort: flexibleInt(fields["port"]),
			Direction:  auditDirection(kind),
		},
		File: model.FileContext{
			Path:       firstPath(paths),
			Operation:  auditFileOperation(fields["nametype"], kind),
			Executable: auditExecutablePath(firstPath(paths)),
		},
		Message:    fmt.Sprintf("Linux audit serial=%s types=%s", assembly.serial, strings.Join(types, ",")),
		Attributes: map[string]interface{}{"audit": auditAttributes},
		Provenance: model.Provenance{
			Source:        sourceID,
			Collector:     "linux-auditd/serial-assembler",
			OriginalPath:  path,
			ContentSHA256: deterministicAuditContentHash(hashes),
		},
	}
	event.Prepare()
	return event
}

func assemblyTimestamp(records []auditRecord) time.Time {
	var timestamp time.Time
	for _, record := range records {
		if timestamp.IsZero() || record.Timestamp.Before(timestamp) {
			timestamp = record.Timestamp
		}
	}
	if timestamp.IsZero() {
		return time.Now().UTC()
	}
	return timestamp.UTC()
}

func auditGroupKind(records []auditRecord) string {
	types := map[string]struct{}{}
	for _, record := range records {
		types[record.TypeName] = struct{}{}
	}
	for _, group := range [][]string{{"AVC", "USER_AVC", "SELINUX_ERR"}, {"CONFIG_CHANGE"}, {"USER_AUTH", "USER_LOGIN", "USER_ACCT", "CRED_ACQ", "CRED_DISP"}, {"SERVICE_STOP"}, {"SERVICE_START"}, {"ADD_USER"}, {"DEL_USER"}, {"ADD_GROUP", "DEL_GROUP", "GRP_MGMT"}, {"EXECVE", "USER_CMD"}, {"SYSCALL"}, {"PATH", "CWD"}} {
		for _, typeName := range group {
			if _, exists := types[typeName]; exists {
				return auditEventKind(typeName, auditGroupFields(records))
			}
		}
	}
	return "linux.audit"
}

func auditGroupSeverity(records []auditRecord) model.Severity {
	severity := model.SeverityInfo
	for _, record := range records {
		candidate := auditSeverity(record.TypeName, record.Fields)
		if severityRank(candidate) > severityRank(severity) {
			severity = candidate
		}
	}
	return severity
}

func severityRank(value model.Severity) int {
	switch value {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}

func auditGroupFields(records []auditRecord) map[string]string {
	result := map[string]string{}
	ordered := append([]auditRecord(nil), records...)
	sort.Slice(ordered, func(i, j int) bool {
		left, right := auditFieldPriority(ordered[i].TypeName), auditFieldPriority(ordered[j].TypeName)
		if left != right {
			return left < right
		}
		return ordered[i].Hash < ordered[j].Hash
	})
	for _, record := range ordered {
		for key, value := range record.Fields {
			if value == "" || result[key] != "" {
				continue
			}
			result[key] = value
		}
	}
	return result
}

func auditFieldPriority(typeName string) int {
	switch typeName {
	case "SYSCALL":
		return 1
	case "EXECVE":
		return 2
	case "USER_CMD":
		return 3
	case "PROCTITLE":
		return 4
	case "CWD":
		return 5
	case "PATH":
		return 6
	default:
		return 10
	}
}

func auditGroupCommandLine(records []auditRecord) string {
	for _, record := range records {
		if record.TypeName == "USER_CMD" {
			if command := firstNonEmpty(record.Fields["cmd"], record.Fields["command"]); command != "" {
				return command
			}
		}
	}
	for _, record := range records {
		if record.TypeName == "EXECVE" {
			if command := auditCommandLine(record.Fields); command != "" {
				return command
			}
		}
	}
	for _, record := range records {
		if record.TypeName == "PROCTITLE" {
			if command := decodeAuditHex(record.Fields["proctitle"]); command != "" {
				return command
			}
		}
	}
	return ""
}

func auditGroupPaths(records []auditRecord) []string {
	seen := map[string]struct{}{}
	paths := make([]string, 0)
	for _, record := range records {
		if record.TypeName != "PATH" {
			continue
		}
		path := firstNonEmpty(record.Fields["name"], record.Fields["path"])
		if path == "" {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func auditGroupSocket(records []auditRecord) map[string]interface{} {
	for _, record := range records {
		if record.TypeName != "SOCKADDR" {
			continue
		}
		if socket := parseAuditSocketAddress(record.Fields["saddr"]); len(socket) > 0 {
			return socket
		}
	}
	return nil
}

func parseAuditSocketAddress(value string) map[string]interface{} {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) < 2 {
		return nil
	}
	family := binary.LittleEndian.Uint16(decoded[:2])
	result := map[string]interface{}{"family": family}
	switch family {
	case 2: // AF_INET: native-endian family, network-endian port/address.
		if len(decoded) < 8 {
			return result
		}
		result["address"] = net.IP(decoded[4:8]).String()
		result["port"] = int(binary.BigEndian.Uint16(decoded[2:4]))
	case 10: // AF_INET6
		if len(decoded) < 24 {
			return result
		}
		result["address"] = net.IP(decoded[8:24]).String()
		result["port"] = int(binary.BigEndian.Uint16(decoded[2:4]))
	case 1: // AF_UNIX
		if len(decoded) > 2 {
			result["path"] = strings.TrimRight(string(decoded[2:]), "\x00")
		}
	}
	return result
}

func auditRecordSummaries(records []auditRecord) []map[string]interface{} {
	summaries := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		summaries = append(summaries, map[string]interface{}{
			"type":   record.TypeName,
			"sha256": record.Hash,
			"fields": auditEvidenceFields(record.Fields),
		})
	}
	return summaries
}

func auditSuccessValue(fields map[string]string) interface{} {
	value := firstNonEmpty(fields["success"], fields["res"], fields["result"])
	if value == "" {
		return nil
	}
	return auditSucceeded(fields)
}

func auditExitValue(fields map[string]string) interface{} {
	value := strings.TrimSpace(fields["exit"])
	if value == "" {
		return nil
	}
	if exitCode, err := strconv.ParseInt(value, 10, 64); err == nil {
		return exitCode
	}
	// Preserve unusual audit values as evidence without treating them as a
	// trusted numeric value.
	return value
}

func firstPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func deterministicAuditContentHash(hashes []string) string {
	digest := sha256.Sum256([]byte(strings.Join(hashes, ",")))
	return hex.EncodeToString(digest[:])
}
