package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
)

func TestAuditAssemblerCombinesOutOfOrderSerialRecords(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 8, MaxRecordsPerSerial: 16, MaxBytesPerSerial: 64 * 1024, AssemblyTimeout: time.Second})
	base := time.Unix(1786017600, 0).UTC()
	lines := []string{
		`type=PATH msg=audit(1786017600.125:812): item=0 name="/tmp/dropper" nametype=CREATE`,
		`type=SOCKADDR msg=audit(1786017600.125:812): saddr=020001BBC0000201`,
		`type=PROCTITLE msg=audit(1786017600.125:812): proctitle=2F62617368002D63006964`,
		`type=SYSCALL msg=audit(1786017600.125:812): arch=c000003e syscall=59 success=yes exit=0 pid=421 ppid=400 uid=1000 euid=1001 suid=1002 fsuid=1003 gid=1000 egid=1004 auid=1000 ses=7 exe="/usr/bin/bash"`,
		`type=CWD msg=audit(1786017600.125:812): cwd="/srv/app"`,
		`type=EXECVE msg=audit(1786017600.125:812): argc=2 a0="/bin/bash" a1="-c"`,
		`type=EOE msg=audit(1786017600.125:812):`,
	}
	var offset int64
	for _, line := range lines {
		record, err := parseAuditRecord(line)
		if err != nil {
			t.Fatal(err)
		}
		offset += int64(len(line) + 1)
		assembler.Add(record, offset, base)
	}
	assembler.FlushExpired(base.Add(2 * time.Second))
	events, groups := assembler.Ready(8, "linux-audit", "/var/log/audit/audit.log")
	if len(events) != 1 || len(groups) != 1 {
		t.Fatalf("expected one assembled event, got events=%d groups=%d", len(events), len(groups))
	}
	event := events[0]
	if event.Kind != "process.start" || event.Process.PID != 421 || event.Process.PPID != 400 {
		t.Fatalf("unexpected assembled process event: %#v", event)
	}
	if event.Process.CommandLine != "/bin/bash -c" || event.Process.Image != "/usr/bin/bash" {
		t.Fatalf("unexpected process context: %#v", event.Process)
	}
	audit := event.Attributes["audit"].(map[string]interface{})
	if audit["partial"] != false {
		t.Fatalf("EOE-terminated serial was unexpectedly partial: %#v", audit)
	}
	if audit["serial"] != "812" || audit["syscall"] != "59" || audit["success"] != true || audit["exit_code"] != int64(0) {
		t.Fatalf("missing syscall fields: %#v", audit)
	}
	identity := audit["identity"].(map[string]string)
	for key, want := range map[string]string{"uid": "1000", "euid": "1001", "suid": "1002", "fsuid": "1003", "gid": "1000", "egid": "1004", "auid": "1000", "ses": "7"} {
		if identity[key] != want {
			t.Fatalf("identity %s: got %q want %q", key, identity[key], want)
		}
	}
	paths := audit["affected_paths"].([]string)
	if len(paths) != 1 || paths[0] != "/tmp/dropper" || audit["cwd"] != "/srv/app" {
		t.Fatalf("unexpected file context: %#v", audit)
	}
	socket := audit["socket_address"].(map[string]interface{})
	if socket["address"] != "192.0.2.1" || socket["port"] != 443 {
		t.Fatalf("unexpected socket address: %#v", socket)
	}
	hashes := audit["raw_record_sha256"].([]string)
	if len(hashes) != len(lines) {
		t.Fatalf("expected %d raw record hashes, got %#v", len(lines), hashes)
	}
	if event.Timestamp != base.Add(125*time.Millisecond) {
		t.Fatalf("unexpected timestamp: %s", event.Timestamp)
	}
}

func TestAuditAssemblerSupportsRequiredRecordFamilies(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 32, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: time.Second})
	base := time.Unix(1786017600, 0).UTC()
	testCases := []struct {
		typeName string
		fields   string
		wantKind string
	}{
		{"USER_CMD", `pid=31 uid=1000 cmd="/usr/bin/id"`, "process.start"},
		{"USER_AUTH", `pid=32 acct="alice" res=failed`, "auth.failure"},
		{"USER_LOGIN", `pid=33 acct="alice" res=success`, "auth.success"},
		{"CONFIG_CHANGE", `op=remove_rule auid=0`, "security.audit_config"},
		{"AVC", `pid=34 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file perms=read`, "security.selinux_denial"},
		{"USER_AVC", `pid=35 scontext=system_u:system_r:sshd_t:s0 tcontext=system_u:object_r:etc_t:s0`, "security.selinux_denial"},
		{"SERVICE_START", `pid=36 unit=sshd.service`, "service.start"},
		{"SERVICE_STOP", `pid=37 unit=sshd.service`, "service.stop"},
		{"ADD_USER", `pid=38 acct="newuser"`, "identity.account_create"},
		{"DEL_USER", `pid=39 acct="olduser"`, "identity.account_delete"},
		{"ADD_GROUP", `pid=40 grp="ops"`, "identity.group_modify"},
		{"DEL_GROUP", `pid=41 grp="oldops"`, "identity.group_modify"},
	}
	for index, testCase := range testCases {
		serial := 1000 + index
		line := fmt.Sprintf("type=%s msg=audit(1786017600.000:%d): %s", testCase.typeName, serial, testCase.fields)
		record, err := parseAuditRecord(line)
		if err != nil {
			t.Fatalf("parse %s: %v", testCase.typeName, err)
		}
		assembler.Add(record, int64(index*2+1), base)
		eoe, err := parseAuditRecord(fmt.Sprintf("type=EOE msg=audit(1786017600.000:%d):", serial))
		if err != nil {
			t.Fatalf("parse EOE for %s: %v", testCase.typeName, err)
		}
		assembler.Add(eoe, int64(index*2+2), base)
	}
	assembler.FlushExpired(base.Add(2 * time.Second))
	events, _ := assembler.Ready(32, "linux-audit", "/var/log/audit/audit.log")
	if len(events) != len(testCases) {
		t.Fatalf("expected %d events, got %d", len(testCases), len(events))
	}
	for index, event := range events {
		if event.Kind != testCases[index].wantKind {
			t.Fatalf("%s kind: got %q want %q", testCases[index].typeName, event.Kind, testCases[index].wantKind)
		}
		if testCases[index].typeName == "AVC" {
			audit := event.Attributes["audit"].(map[string]interface{})
			context := audit["selinux_context"].(map[string]string)
			if context["scontext"] == "" || context["tcontext"] == "" {
				t.Fatalf("SELinux context missing from AVC event: %#v", audit)
			}
		}
	}
}

func TestParseAuditRecordUsesKernelEnvelopeWithDuplicateMessageField(t *testing.T) {
	line := `type=USER_CMD msg=audit(1786017600.250:1201): pid=31 uid=1000 auid=1000 msg='cwd="/srv/app" cmd=/usr/bin/id terminal=pts/1 res=success'`
	record, err := parseAuditRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	if record.Serial != "1201" || !record.Timestamp.Equal(time.Unix(1786017600, 250000000).UTC()) {
		t.Fatalf("unexpected audit envelope: serial=%q timestamp=%s", record.Serial, record.Timestamp)
	}
	if record.Fields["msg"] == "" || strings.Contains(record.Fields["msg"], "audit(") {
		t.Fatalf("expected the application msg field to remain available as evidence: %#v", record.Fields)
	}
}

func TestAuditAssemblerDeterministicAcrossRecordOrder(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1786017600.000:900): syscall=59 success=yes pid=20 exe="/bin/sh"`,
		`type=EXECVE msg=audit(1786017600.000:900): argc=1 a0="/bin/sh"`,
		`type=PATH msg=audit(1786017600.000:900): item=0 name="/tmp/x" nametype=CREATE`,
	}
	assemble := func(order []int) string {
		assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 4, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: time.Second})
		for index, lineIndex := range order {
			record, err := parseAuditRecord(lines[lineIndex])
			if err != nil {
				t.Fatal(err)
			}
			assembler.Add(record, int64(index+1), time.Unix(1, 0))
		}
		assembler.FlushAll("end_of_input")
		events, _ := assembler.Ready(1, "linux-audit", "/var/log/audit/audit.log")
		return events[0].ID
	}
	if first, second := assemble([]int{0, 1, 2}), assemble([]int{2, 0, 1}); first != second {
		t.Fatalf("event ID changed with record order: %s != %s", first, second)
	}
}

func TestAuditAssemblerBoundsAndTimeoutProducePartialEvents(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 1, MaxRecordsPerSerial: 1, MaxBytesPerSerial: 4096, AssemblyTimeout: 100 * time.Millisecond})
	first, err := parseAuditRecord(`type=SYSCALL msg=audit(10.0:2): syscall=59 pid=2`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseAuditRecord(`type=EXECVE msg=audit(10.0:2): a0="/bin/sh"`)
	if err != nil {
		t.Fatal(err)
	}
	third, err := parseAuditRecord(`type=SYSCALL msg=audit(10.0:1): syscall=59 pid=1`)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(10, 0)
	assembler.Add(first, 10, base)
	assembler.Add(second, 20, base)
	assembler.Add(third, 30, base)
	assembler.FlushExpired(base.Add(time.Second))
	events, _ := assembler.Ready(8, "linux-audit", "/var/log/audit/audit.log")
	if len(events) != 3 {
		t.Fatalf("expected bounded partial events, got %d", len(events))
	}
	for _, event := range events {
		audit := event.Attributes["audit"].(map[string]interface{})
		if audit["partial"] != true || audit["partial_reason"] == "" {
			t.Fatalf("expected partial indicator: %#v", audit)
		}
	}
	stats := assembler.Stats()
	if stats.IncompleteAssemblies < 3 || stats.ActiveSerials != 0 {
		t.Fatalf("unexpected assembler stats: %#v", stats)
	}
}

func TestAuditAssemblerEvictsOldestSerialDeterministically(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 2, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: time.Second})
	base := time.Unix(1786017600, 0).UTC()
	for index, serial := range []string{"20", "10", "30"} {
		record, err := parseAuditRecord(fmt.Sprintf("type=SYSCALL msg=audit(1786017600.000:%s): syscall=59 pid=%d", serial, index+1))
		if err != nil {
			t.Fatal(err)
		}
		assembler.Add(record, int64(index+1), base)
	}
	events, _ := assembler.Ready(1, "linux-audit", "/var/log/audit/audit.log")
	if len(events) != 1 {
		t.Fatalf("expected evicted event, got %d", len(events))
	}
	audit := events[0].Attributes["audit"].(map[string]interface{})
	if audit["serial"] != "10" || audit["partial_reason"] != "max_active_serials" {
		t.Fatalf("eviction was not stable by serial tie-break: %#v", audit)
	}
}

func TestAuditAssemblerDropsOversizedRecordWithinBound(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 1, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: time.Second})
	line := `type=EXECVE msg=audit(1786017600.000:700): a0="` + strings.Repeat("x", 5000) + `"`
	record, err := parseAuditRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	assembler.Add(record, int64(len(line)), time.Unix(1786017600, 0))
	events, _ := assembler.Ready(1, "linux-audit", "/var/log/audit/audit.log")
	if len(events) != 1 {
		t.Fatalf("expected oversized-record partial event, got %d", len(events))
	}
	audit := events[0].Attributes["audit"].(map[string]interface{})
	if audit["partial_reason"] != "record_exceeds_max_bytes_per_serial" {
		t.Fatalf("unexpected partial reason: %#v", audit)
	}
	if stats := assembler.Stats(); stats.DroppedRecords != 1 || stats.IncompleteAssemblies != 1 {
		t.Fatalf("oversized record counters are wrong: %#v", stats)
	}
}

func TestAuditAssemblerCompactsAcknowledgedGroupsBehindCursorBlocker(t *testing.T) {
	assembler := mustAuditAssembler(t, AuditAssemblerOptions{MaxActiveSerials: 128, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: time.Second})
	base := time.Unix(1786017600, 0).UTC()
	blocker, err := parseAuditRecord(`type=SYSCALL msg=audit(1786017600.000:1): syscall=59 pid=1`)
	if err != nil {
		t.Fatal(err)
	}
	assembler.Add(blocker, 1, base)
	for serial := 2; serial <= 64; serial++ {
		record, err := parseAuditRecord(fmt.Sprintf("type=SYSCALL msg=audit(1786017600.000:%d): syscall=59 pid=%d", serial, serial))
		if err != nil {
			t.Fatal(err)
		}
		eoe, err := parseAuditRecord(fmt.Sprintf("type=EOE msg=audit(1786017600.000:%d):", serial))
		if err != nil {
			t.Fatal(err)
		}
		assembler.Add(record, int64(serial*2), base)
		assembler.Add(eoe, int64(serial*2+1), base)
	}
	assembler.FlushAll("test_complete")
	_, groups := assembler.Ready(128, "linux-audit", "/var/log/audit/audit.log")
	if len(groups) != 64 {
		t.Fatalf("expected blocker plus 63 completed groups, got %d", len(groups))
	}
	assembler.Acknowledge(groups[1:])
	if len(assembler.slots) != 2 {
		t.Fatalf("acknowledged groups were not compacted: %d slots", len(assembler.slots))
	}
	if got := assembler.slots[1]; !got.safe || got.endOffset != int64(64*2+1) {
		t.Fatalf("unexpected compacted cursor watermark: %#v", got)
	}
	for _, group := range groups[1:] {
		if group.records != nil {
			t.Fatal("acknowledged record payload was retained")
		}
	}
}

func TestAuditSourceCursorWaitsForAssembledEventAcknowledgement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cursor, err := openCursor(directory, "linux-audit", "auditd")
	if err != nil {
		t.Fatal(err)
	}
	sourceInterface, err := newAuditSource(config.NativeSource{
		ID: "linux-audit", Kind: "auditd", Path: path, FromStart: true, MaxBatch: 32,
		MaxActiveSerials: 4, MaxRecordsPerSerial: 8, MaxBytesPerSerial: 4096, AssemblyTimeout: "1m",
	}, cursor)
	if err != nil {
		t.Fatal(err)
	}
	source := sourceInterface.(*auditSource)
	initial, errs := source.Poll(context.Background())
	if len(errs) != 0 {
		t.Fatalf("initial poll errors: %v", errs)
	}
	if err := initial.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	line := `type=SYSCALL msg=audit(1786017600.000:812): syscall=59 success=yes pid=421 exe="/bin/sh"` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	batch, errs := source.Poll(context.Background())
	if len(errs) != 0 || len(batch.Events) != 0 {
		t.Fatalf("incomplete serial should not be emitted: events=%d errors=%v", len(batch.Events), errs)
	}
	if state := cursor.Snapshot(); state.FileOffset != 0 {
		t.Fatalf("cursor advanced before assembly: %#v", state)
	}
	source.assembler.FlushAll("test_complete")
	batch, errs = source.Poll(context.Background())
	if len(errs) != 0 || len(batch.Events) != 1 {
		t.Fatalf("expected one assembled event: events=%d errors=%v", len(batch.Events), errs)
	}
	if state := cursor.Snapshot(); state.FileOffset != 0 {
		t.Fatalf("cursor advanced before evidence acknowledgement: %#v", state)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if state := cursor.Snapshot(); state.FileOffset != int64(len(line)) {
		t.Fatalf("cursor did not advance after acknowledgement: %#v", state)
	}
}

func TestAuditSourceFlushesPartialSerialBeforeRotation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file-identity rotation behavior is Linux-specific")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	source, cursor := mustAuditSource(t, directory, path)
	initializeAuditSource(t, source)
	line := `type=SYSCALL msg=audit(1786017600.000:900): syscall=59 pid=20 exe="/bin/sh"` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if batch, errs := source.Poll(context.Background()); len(errs) != 0 || len(batch.Events) != 0 {
		t.Fatalf("expected active serial before rotation: events=%d errors=%v", len(batch.Events), errs)
	}
	previous, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	batch, errs := source.Poll(context.Background())
	if len(errs) != 0 || len(batch.Events) != 1 {
		t.Fatalf("rotation did not flush partial serial: events=%d errors=%v", len(batch.Events), errs)
	}
	audit := batch.Events[0].Attributes["audit"].(map[string]interface{})
	if audit["partial_reason"] != "audit_log_rotated_or_truncated" {
		t.Fatalf("unexpected rotation partial reason: %#v", audit)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	current, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	oldDevice, oldInode := platformFileIdentity(previous)
	newDevice, newInode := platformFileIdentity(current)
	if oldDevice == newDevice && oldInode == newInode {
		t.Fatal("test setup did not rotate the audit log")
	}
	state := cursor.Snapshot()
	if state.FileOffset != 0 || state.FileDevice != newDevice || state.FileInode != newInode {
		t.Fatalf("cursor did not switch atomically to rotated log: %#v", state)
	}
}

func TestAuditSourceFlushesPartialSerialBeforeTruncation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file-identity truncation behavior is Linux-specific")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	source, cursor := mustAuditSource(t, directory, path)
	initializeAuditSource(t, source)
	line := `type=SYSCALL msg=audit(1786017600.000:901): syscall=59 pid=20 exe="/bin/sh"` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if batch, errs := source.Poll(context.Background()); len(errs) != 0 || len(batch.Events) != 0 {
		t.Fatalf("expected active serial before truncation: events=%d errors=%v", len(batch.Events), errs)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	batch, errs := source.Poll(context.Background())
	if len(errs) != 0 || len(batch.Events) != 1 {
		t.Fatalf("truncation did not flush partial serial: events=%d errors=%v", len(batch.Events), errs)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
	if state := cursor.Snapshot(); state.FileOffset != 0 {
		t.Fatalf("cursor did not reset after truncation: %#v", state)
	}
}

func mustAuditSource(t *testing.T, directory, path string) (*auditSource, *cursorFile) {
	t.Helper()
	cursor, err := openCursor(directory, "linux-audit", "auditd")
	if err != nil {
		t.Fatal(err)
	}
	sourceInterface, err := newAuditSource(config.NativeSource{
		ID:                  "linux-audit",
		Kind:                "auditd",
		Path:                path,
		FromStart:           true,
		MaxBatch:            32,
		MaxActiveSerials:    4,
		MaxRecordsPerSerial: 8,
		MaxBytesPerSerial:   4096,
		AssemblyTimeout:     "1m",
	}, cursor)
	if err != nil {
		t.Fatal(err)
	}
	return sourceInterface.(*auditSource), cursor
}

func initializeAuditSource(t *testing.T, source *auditSource) {
	t.Helper()
	batch, errs := source.Poll(context.Background())
	if len(errs) != 0 {
		t.Fatalf("initial poll errors: %v", errs)
	}
	if err := batch.Acknowledge(); err != nil {
		t.Fatal(err)
	}
}

func mustAuditAssembler(t *testing.T, options AuditAssemblerOptions) *auditAssembler {
	t.Helper()
	assembler, err := newAuditAssembler(options)
	if err != nil {
		t.Fatal(err)
	}
	return assembler
}
