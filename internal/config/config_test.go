package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsRemoteAPI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"poll_interval":"1s","api":{"enabled":true,"listen":"0.0.0.0:9477"}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected remote API address to be rejected")
	}
}

func TestLoadResolvesPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"data_dir":"state","poll_interval":"1s","api":{"enabled":false},"tools":{"policy_file":"policy.json","allowed_paths":["logs"]}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != filepath.Join(dir, "state") {
		t.Fatalf("unexpected data dir: %s", cfg.DataDir)
	}
	if cfg.Tools.AllowedPaths[0] != filepath.Join(dir, "logs") {
		t.Fatalf("unexpected allowed path: %s", cfg.Tools.AllowedPaths[0])
	}
}

func TestLoadResolvesCentralPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"data_dir":"state",
		"poll_interval":"1s",
		"api":{"enabled":false},
		"central":{
			"enabled":true,
			"url":"https://central.example",
			"enrollment_token_file":"/etc/ntagentshield/enrollment.token"
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Central.APIKeyFile != filepath.Join(dir, "state", "central-api.key") {
		t.Fatalf("unexpected Central API key path: %s", cfg.Central.APIKeyFile)
	}
	if cfg.Central.EnrollmentTokenFile != "/etc/ntagentshield/enrollment.token" {
		t.Fatalf("unexpected enrollment token path: %s", cfg.Central.EnrollmentTokenFile)
	}
}

func TestLoadResolvesAndValidatesAutomaticAISettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"data_dir":"state",
		"poll_interval":"1s",
		"api":{"enabled":false},
		"ai":{
			"enabled":true,
			"endpoint":"https://central.example/api/v1/llm/v1",
			"model":"qwen3.5-9b",
			"api_key_file":"llm.token",
			"allow_remote":true,
			"auto_analyze":true,
			"minimum_severity":"high",
			"queue_size":32,
			"min_interval":"15s",
			"audit_log_file":"llm.audit.jsonl"
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AI.APIKeyFile != filepath.Join(dir, "state", "llm.token") {
		t.Fatalf("unexpected AI key path: %s", cfg.AI.APIKeyFile)
	}
	if cfg.AI.AuditLogFile != filepath.Join(dir, "state", "llm.audit.jsonl") {
		t.Fatalf("unexpected AI audit path: %s", cfg.AI.AuditLogFile)
	}

	invalid := strings.Replace(content, `"queue_size":32`, `"queue_size":2048`, 1)
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected excessive AI queue size to be rejected")
	}
}

func TestLoadValidatesNativeSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"native_sources":[
			{"id":"sysmon-operational","enabled":true,"kind":"windows_eventlog","channel":"Microsoft-Windows-Sysmon/Operational","event_ids":[1,3,11,22]},
			{"id":"system-journal","enabled":true,"kind":"journald","units":["sshd.service"],"identifiers":["sudo"]},
			{"id":"linux-audit","enabled":true,"kind":"auditd","path":"logs/audit.log"}
		]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.NativeSources) != 3 {
		t.Fatalf("expected three native sources, got %d", len(cfg.NativeSources))
	}
	if cfg.NativeSources[0].MaxBatch != 256 || cfg.NativeSources[0].CommandTimeout != "15s" {
		t.Fatalf("native defaults were not applied: %#v", cfg.NativeSources[0])
	}
	if cfg.NativeSources[2].MaxActiveSerials != 128 || cfg.NativeSources[2].MaxRecordsPerSerial != 64 || cfg.NativeSources[2].MaxBytesPerSerial != 64*1024 || cfg.NativeSources[2].AssemblyTimeout != "2s" {
		t.Fatalf("audit assembler defaults were not applied: %#v", cfg.NativeSources[2])
	}
	if cfg.NativeSources[2].Path != filepath.Join(dir, "logs", "audit.log") {
		t.Fatalf("audit path was not resolved: %s", cfg.NativeSources[2].Path)
	}
	if !cfg.ProcessGraph.Enabled || cfg.ProcessGraph.ReconcileInterval != "30s" || cfg.ProcessGraph.MaxProcesses != 4096 || cfg.ProcessGraph.MaxExitedProcesses != 2048 || cfg.ProcessGraph.MaxCommandLineBytes != 4096 || cfg.ProcessGraph.MaxExecutableHashBytes != 128*1024*1024 {
		t.Fatalf("process graph defaults were not applied: %#v", cfg.ProcessGraph)
	}
	if !cfg.ProcessNetwork.Enabled || cfg.ProcessNetwork.ReconcileInterval != "30s" || cfg.ProcessNetwork.MaxProcesses != 4096 || cfg.ProcessNetwork.MaxSockets != 8192 || cfg.ProcessNetwork.MaxFileDescriptors != 65536 {
		t.Fatalf("process network defaults were not applied: %#v", cfg.ProcessNetwork)
	}
	if !cfg.EBPFSensor.Enabled || cfg.EBPFSensor.RingBufferBytes != 16*1024*1024 || cfg.EBPFSensor.MaxEventsPerSec != 20000 {
		t.Fatalf("eBPF sensor defaults were not applied: %#v", cfg.EBPFSensor)
	}
	if cfg.PrivilegeSeparation.SensorSocket != "/run/ntagentshield-sensor/sensor.sock" || cfg.PrivilegeSeparation.ResponseSocket != "/run/ntagentshield-response/response.sock" || cfg.PrivilegeSeparation.MaxMessageBytes != 256*1024 || cfg.PrivilegeSeparation.RequestTimeout != "5s" {
		t.Fatalf("privilege-separation defaults were not applied: %#v", cfg.PrivilegeSeparation)
	}
}

func TestLoadValidatesPrivilegeSeparationBounds(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	testCases := []string{
		`{"poll_interval":"1s","api":{"enabled":false},"privilege_separation":{"enabled":true,"sensor_socket":"relative.sock","response_socket":"/run/response.sock","max_message_bytes":262144,"request_timeout":"5s"}}`,
		`{"poll_interval":"1s","api":{"enabled":false},"privilege_separation":{"enabled":true,"sensor_socket":"/run/same.sock","response_socket":"/run/same.sock","max_message_bytes":262144,"request_timeout":"5s"}}`,
		`{"poll_interval":"1s","api":{"enabled":false},"privilege_separation":{"enabled":true,"sensor_socket":"/run/sensor.sock","response_socket":"/run/response.sock","max_message_bytes":2097152,"request_timeout":"5s"}}`,
		`{"poll_interval":"1s","api":{"enabled":false},"privilege_separation":{"enabled":true,"sensor_socket":"/run/sensor.sock","response_socket":"/run/response.sock","max_message_bytes":262144,"request_timeout":"10ms"}}`,
	}
	for index, content := range testCases {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: unsafe privilege-separation configuration was accepted", index)
		}
	}
}

func TestLoadAppliesAndValidatesDetectionSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"detection":{"auth_failure_threshold":4,"auth_failure_window":"90s"}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Detection.AuthFailureThreshold != 4 || cfg.Detection.AuthFailureWindow != "90s" {
		t.Fatalf("unexpected detection settings: %#v", cfg.Detection)
	}

	invalidPath := filepath.Join(dir, "invalid.json")
	invalid := `{"poll_interval":"1s","api":{"enabled":false},"detection":{"auth_failure_threshold":1,"auth_failure_window":"5m"}}`
	if err := os.WriteFile(invalidPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(invalidPath); err == nil {
		t.Fatal("expected unsafe authentication failure threshold to be rejected")
	}
}

func TestLoadRejectsUnsafeAuditAssemblerBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"native_sources":[{
			"id":"linux-audit","enabled":true,"kind":"auditd","path":"/var/log/audit/audit.log",
			"max_active_serials":1024,"max_records_per_serial":64,"max_bytes_per_serial":65536,"assembly_timeout":"2s"
		}]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected excessive audit assembler memory budget to be rejected")
	}
}

func TestLoadRejectsUnsafeAuditPendingBatchBudget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"native_sources":[{
			"id":"linux-audit","enabled":true,"kind":"auditd","path":"/var/log/audit/audit.log",
			"max_batch":512,"max_active_serials":128,"max_records_per_serial":64,"max_bytes_per_serial":65536,"assembly_timeout":"2s"
		}]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe pending audit batch budget to be rejected")
	}
}

func TestLoadRejectsUnsafeProcessGraphBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"process_graph":{"enabled":true,"reconcile_interval":"500ms","max_processes":4096,"max_exited_processes":2048,"max_command_line_bytes":4096,"max_executable_hash_bytes":134217728}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe process graph interval to be rejected")
	}

	content = `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"process_graph":{"enabled":true,"reconcile_interval":"30s","max_processes":16384,"max_exited_processes":16384,"max_command_line_bytes":65536,"max_executable_hash_bytes":134217728}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected excessive process graph memory budget to be rejected")
	}
}

func TestLoadRejectsUnsafeProcessNetworkBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"process_network":{"enabled":true,"reconcile_interval":"500ms","max_processes":4096,"max_sockets":8192,"max_file_descriptors":65536}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe process network interval to be rejected")
	}

	content = `{
		"poll_interval":"1s",
		"api":{"enabled":false},
		"process_network":{"enabled":true,"reconcile_interval":"30s","max_processes":4096,"max_sockets":32768,"max_file_descriptors":8192}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected incompatible process network bounds to be rejected")
	}
}

func TestLoadRejectsUnsafeEBPFSensorBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	content := `{"poll_interval":"1s","api":{"enabled":false},"ebpf_sensor":{"enabled":true,"ring_buffer_bytes":12345,"max_events_per_sec":20000}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid eBPF ring buffer to be rejected")
	}
	content = `{"poll_interval":"1s","api":{"enabled":false},"ebpf_sensor":{"enabled":true,"ring_buffer_bytes":16777216,"max_events_per_sec":100001}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unsafe eBPF event rate to be rejected")
	}
}

func TestLoadRejectsUnsafeNativeSourceConfiguration(t *testing.T) {
	testCases := []string{
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"../cursor","enabled":true,"kind":"journald","units":["sshd.service"]}]}`,
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"security","enabled":true,"kind":"windows_eventlog","channel":"Security\n/q:*"}]}`,
		`{"poll_interval":"1s","api":{"enabled":false},"native_sources":[{"id":"journal","enabled":true,"kind":"journald","units":["sshd.service\n--output=cat"]}]}`,
	}
	for index, content := range testCases {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: expected unsafe native source configuration to be rejected", index)
		}
	}
}

func TestEnsureAgentIDPersists(t *testing.T) {
	dir := t.TempDir()
	first := Config{DataDir: dir}
	if err := EnsureAgentID(&first); err != nil {
		t.Fatal(err)
	}
	second := Config{DataDir: dir}
	if err := EnsureAgentID(&second); err != nil {
		t.Fatal(err)
	}
	if first.AgentID == "" || first.AgentID != second.AgentID {
		t.Fatalf("agent identity was not stable: %q %q", first.AgentID, second.AgentID)
	}
}
