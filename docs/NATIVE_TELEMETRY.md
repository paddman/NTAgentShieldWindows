# Native Event Telemetry

NTAgentShield collects operating-system security telemetry directly from Windows Event Log, Sysmon, Linux journald, and auditd. Native collectors feed the same redaction, tamper-evident journal, deterministic detection, and policy boundary used by file and API ingestion.

## Security boundary

Native telemetry is evidence, not instruction.

- Every event is marked `untrusted_telemetry`.
- Process command lines, event messages, account names, paths, journal fields, and audit fields are recursively redacted before persistence or AI transfer.
- The AI investigator receives no action tools.
- Native source configuration does not accept arbitrary shell commands, PowerShell snippets, XPath, or journalctl arguments.
- Windows channels, Event IDs, journald units/identifiers, and audit paths are schema-validated.
- Operating-system commands and arguments are fixed in the collector implementation.
- Each command has a timeout and bounded output.
- Cursor files are local state, not model context.

The read-only `ntagentshield-doctor` command checks kernel/BTF availability, auditd and journald access, nftables, current capabilities, filesystem modes, mTLS certificate validity and Control Plane connectivity, plus outbox health. It runs only fixed probes with timeouts and bounded output; it does not install packages, change permissions, load eBPF, mutate the outbox, or run a shell.

## At-least-once evidence delivery

Each source returns a batch plus a proposed cursor. Runtime processing follows this order:

```text
collect batch
  -> normalize events
  -> redact secrets
  -> append events to evidence journal
  -> run deterministic detections
  -> append findings
  -> acknowledge and persist source cursor
```

The cursor does not advance if event or finding persistence fails. A retry may therefore produce the same event again. Native event IDs are deterministic from stable source coordinates such as Windows `EventRecordID`, journald cursor, or audit serial plus line hash, allowing downstream deduplication without accepting silent evidence loss.

Cursor state is stored below:

```text
<data_dir>/cursors/<source-id>.json
```

Cursor files and directories are created with restrictive permissions. Source IDs are constrained to safe filename characters.

## First-run behavior

`from_start` controls initial position:

- `false` records the current tail and begins with newly arriving evidence.
- `true` starts from the oldest available Windows/journal record or byte zero for auditd.

For auditd, a `from_start=true` source initializes byte offset zero on the first poll and starts producing events on the next poll. This keeps cursor initialization explicit and replayable.

## Windows Event Log and Sysmon

The Windows collector invokes `wevtutil.exe` directly. It does not invoke `cmd.exe` or PowerShell and does not accept free-form XPath.

Supported configuration:

```json
{
  "id": "sysmon-operational",
  "enabled": true,
  "kind": "sysmon",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "event_ids": [1, 3, 4, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 25, 26, 29],
  "from_start": false,
  "max_batch": 512,
  "command_timeout": "20s"
}
```

Important mappings:

| Provider/Event | NTAgentShield kind |
|---|---|
| Sysmon 1 | `process.start` |
| Sysmon 3 | `network.connect` |
| Sysmon 4 | `security.log_service_stopped` |
| Sysmon 8 | `process.remote_thread` |
| Sysmon 10 | `process.access` |
| Sysmon 11 | `file.write` |
| Sysmon 12-14 | `registry.modify` |
| Sysmon 16 | `security.sysmon_config_change` |
| Sysmon 19-21 | `persistence.wmi` |
| Sysmon 22 | `dns.query` |
| Sysmon 25 | `process.tamper` |
| Security 4624/4625 | `auth.success` / `auth.failure` |
| Security 4688 | `process.start` |
| Security 4697 or System 7045 | `service.create` |
| Security 4698-4702 | `persistence.scheduled_task` |
| Security 4719 | `security.audit_config` |
| Security 4720/4722/4724 | account creation, enablement, or password reset |
| Security 4728/4732/4756 | `identity.group_member_add` |
| Security 4946-4948 | `firewall.rule_change` |
| Security 5156/5157 | `network.connect` / `network.block` |
| System 104 or Security 1102 | `security.log_clear` |

### Windows permissions

The service account must be able to query configured channels. Practical deployment choices are:

- Run the Windows service as `LocalSystem`, then harden service ACLs and binary/update paths.
- Use a dedicated service identity with membership in `Event Log Readers`, plus channel-specific ACLs where required.
- Sysmon must be installed and its Operational channel enabled before enabling that source.
- Security log access can require additional local policy depending on the service identity and Windows version.

Do not grant interactive logon to the agent service identity.

## Linux journald

The journald collector invokes `journalctl` directly with fixed flags and validated `--unit` or `--identifier` filters. It requests JSON output and persists the opaque journald cursor.

```json
{
  "id": "linux-auth-journal",
  "enabled": true,
  "kind": "journald",
  "identifiers": ["sshd", "sudo", "su", "polkitd", "cron", "crond", "auditd", "systemd-logind"],
  "from_start": false,
  "max_batch": 1024,
  "command_timeout": "15s"
}
```

Current normalization includes:

- SSH accepted and failed authentication
- SSH session open/close
- sudo activity
- systemd service start/stop messages
- kernel messages
- generic journal evidence

The raw journald cursor is never copied into event attributes. `_BOOT_ID` is replaced with a scoped SHA-256 hash before persistence.

### Journald permissions

On systemd systems, use one of these approaches:

- Run the service with the minimum privileges needed for selected journals.
- Add a dedicated agent identity to `systemd-journal` where distribution policy permits.
- Use ACLs for journal files instead of broad root access.

Availability of fields varies by distribution, journal storage mode, unit, and service identity.

## Linux auditd

The auditd collector reads a validated absolute path, normally:

```text
/var/log/audit/audit.log
```

```json
{
  "id": "linux-audit",
  "enabled": true,
  "kind": "auditd",
  "path": "/var/log/audit/audit.log",
  "from_start": false,
  "max_batch": 256,
  "command_timeout": "15s",
  "max_active_serials": 128,
  "max_records_per_serial": 64,
  "max_bytes_per_serial": 65536,
  "assembly_timeout": "2s"
}
```

The collector tracks device, inode, and byte offset. It resets to byte zero when rotation changes the file identity or truncation moves the file behind the stored offset. A non-newline-terminated fragment is not emitted and does not advance the acknowledged offset.

### Serial assembly and cursor safety

Auditd commonly writes one security operation as several records sharing one audit serial. The Linux collector buffers the supported records (`SYSCALL`, `EXECVE`, `PROCTITLE`, `CWD`, `PATH`, `SOCKADDR`, `USER_*`, `CONFIG_CHANGE`, SELinux, service, and identity records) and emits one normalized event per serial group.

The assembler is deliberately bounded by `max_active_serials`, `max_records_per_serial`, `max_bytes_per_serial`, and `assembly_timeout`. Configuration rejects a combined active-plus-unacknowledged-batch serialized evidence budget above 32 MiB. A timeout, rotation/truncation, or deterministic capacity eviction emits a `partial=true` event with a reason instead of silently discarding evidence. Each event carries the serial, record types, raw-record SHA-256 values, syscall/identity fields, command line, CWD, paths, socket address, and SELinux context when available.

The reader keeps an in-memory read watermark separate from the durable cursor. The durable cursor advances only after the runtime has written the assembled event and all findings to the hash-chained journal, then acknowledged the batch. Acknowledged record payloads are released and their slots collapse to a cursor watermark, so a blocked earlier serial cannot retain later evidence in memory. On rotation or truncation, pending serials are emitted as partial events before the cursor switches to the new file identity. Local status exposes active serials, assembled events, incomplete groups, and dropped records.

Current mappings include:

| Audit type | NTAgentShield kind |
|---|---|
| `EXECVE`, `USER_CMD` | `process.start` |
| `SYSCALL` | `process.syscall` |
| `PATH`, `CWD` | `file.access` |
| `USER_AUTH`, `USER_LOGIN`, `USER_ACCT` | `auth.success` or `auth.failure` |
| `SERVICE_START`, `SERVICE_STOP` | `service.start`, `service.stop` |
| `CONFIG_CHANGE` | `security.audit_config` |
| `AVC`, `USER_AVC`, `SELINUX_ERR` | `security.selinux_denial` |
| `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP` | identity changes |
| `ANOM_*`, `RESP_*` | `security.anomaly` |

### auditd permissions

The agent identity needs read access to the audit log and execute/search permission on parent directories. Prefer ACLs or a narrowly scoped service capability over making the entire process unrestricted. Keep audit log rotation settings compatible with inode/offset tracking.

## Linux process graph

The Linux-only process graph reads fixed `/proc` files directly; it does not invoke a shell or accept remote filters. It emits recovered `process.start` and inferred `process.exit` evidence, then checkpoints its graph only after those events and findings are journaled.

```json
"process_graph": {
  "enabled": true,
  "reconcile_interval": "30s",
  "max_processes": 4096,
  "max_exited_processes": 2048,
  "max_command_line_bytes": 4096,
  "max_executable_hash_bytes": 134217728
}
```

Each node includes a process GUID derived from the boot hash, PID, and start ticks; parent GUID; executable, command line, UID/EUID/GID/EGID, username, login/session identifiers, namespaces, cgroup/container ID, capability masks, executable SHA-256 plus inode/device, and start/stop timestamps. Command lines are redacted before the graph checkpoint is persisted. Permission-denied, disappearing, or scan-capped processes are not treated as exits. Commands and state are bounded; executable hashing is skipped above the configured cap rather than reading an unlimited file.

## Linux process-aware network inventory

The Linux-only network inventory reads only the fixed `/proc/net/{tcp,tcp6,udp,udp6}` tables and `/proc/<pid>/fd` symlinks. It resolves each socket inode only against a graph node whose PID **and** start ticks still match, so PID reuse cannot transfer a socket to a previous process. It produces `network.listen` and `network.connection` evidence with process GUID, PID, executable, user, cgroup/container context, local/remote address, protocol, and socket state.

```json
"process_network": {
  "enabled": true,
  "reconcile_interval": "30s",
  "max_processes": 4096,
  "max_sockets": 8192,
  "max_file_descriptors": 65536
}
```

All scans are bounded. Permission failures and disappearing processes or file descriptors are treated as incomplete observations, never as a reason to infer ownership or issue a response. Newly observed sockets become known only after their event and any findings have been journaled successfully; there is no shell, remote filter, or response interface.

## Linux CO-RE eBPF sensor

The embedded Linux-only sensor attaches a fixed, reviewed CO-RE tracepoint set: process exec/exit; TCP connect/accept; file open/write/rename/unlink; chmod/chown; ptrace; setuid/setgid; module load; and `setns`. It cannot receive an eBPF program, attach point, path, syscall filter, or command from Central, telemetry, or AI.

```json
"ebpf_sensor": {
  "enabled": true,
  "ring_buffer_bytes": 16777216,
  "max_events_per_sec": 20000
}
```

The ring buffer is a power of two from 1–64 MiB and the user-space normalizer bounds delivered events to 100–100,000/sec. Every normalized event is untrusted telemetry and carries the process GUID/container context when the bounded process graph can resolve the exact boot-time identity. The status API reports loaded programs, attached hooks, kernel ring-buffer loss, parse errors, delivery rate, throttling, and last event time.

The sensor requires Linux kernel 5.8+, kernel BTF, and either `CAP_BPF` plus `CAP_PERFMON` or `CAP_SYS_ADMIN`. If any check, program load, or hook attachment fails, it is disabled with a precise health fallback reason; the core agent continues using only its configured auditd and/or journald collectors. It never invokes a shell as fallback.

With `privilege_separation.enabled`, only `ntagentshield-sensor` receives `CAP_BPF` and `CAP_PERFMON`; the Core does not load BPF or retain capabilities. The helper exposes only `sensor.poll` over its local Unix socket. Its 8,192-event queue is bounded, queue loss is reported with sensor health, and one batch remains pending until the Core has persisted every event and finding and returns the exact batch ID. No path, filter, attach point, BPF bytecode, response request, or command is accepted by this interface.

## High-signal native detections

The deterministic engine raises dedicated findings for:

- Windows Security log clear
- Windows/Sysmon telemetry service or configuration changes
- Sysmon process tampering
- Sysmon remote thread creation
- Scheduled task persistence
- Service creation
- Account creation
- Account enablement or password reset
- Privileged-group membership changes
- Windows Firewall rule changes
- Linux audit disablement or weakening
- Other audit-policy changes in heightened mode
- SELinux denials correlated as security evidence

These detections produce findings, not automatic containment. Response still requires deterministic policy and, for state-changing actions, an exact action approval.

### Offline Linux detection pack

The Linux pack evaluates normalized auditd, journald, process-graph, network-inventory, and eBPF evidence locally. It covers web-service-to-shell, `curl`/`wget` piped to an interpreter, reverse-shell primitives and shell network connections, execution from temporary paths, systemd/cron/SSH/PAM/dynamic-linker persistence, user/group and defensive-control changes, security-log deletion/truncation, unusual kernel-module loads, sensitive credential access, container-escape indicators, and NTAgentShield tampering.

Two sequence rules keep bounded local state. File-drop-to-execution retains at most 2,048 normalized paths for 10 minutes. Mass-file modification retains at most 1,024 process identities and 128 distinct paths per process in a 60-second window, alerting at 32 paths. Capacity eviction is deterministic by oldest timestamp and lexical key. State is derived only from untrusted local evidence and cannot supply an instruction, response argument, filter, or program.

Every Linux finding includes stable rule metadata, English and Thai explanations, severity/confidence, MITRE mappings, evidence IDs, a process-tree slot, investigation guidance, and one typed response recommendation. A recommendation is descriptive evidence only: execution still requires the Response Broker, exact action digest, signed policy, short-lived approval lease, and local validation.

## Operational checks

Validate configuration:

```bash
go run ./cmd/ntagentshieldctl doctor --config config/windows.example.json
```

Run the agent and inspect status:

```bash
go run ./cmd/ntagentshield-agent --config config/windows.example.json
```

```bash
TOKEN="$(cat <data_dir>/agent-api.token)"
curl -H "Authorization: Bearer ${TOKEN}" http://127.0.0.1:9477/v1/status
```

Status exposes file/native source counts and the number of processed native events.

Verify the evidence chain after collection:

```bash
go run ./cmd/ntagentshieldctl verify-store --path <data_dir>/evidence.journal.jsonl
```

## Current limitations

- Windows collection uses bounded polling through `wevtutil`, not a push subscription or ETW callback yet.
- Windows XML rendering varies by provider and locale; normalized fields are extracted from provider data first, with rendered text retained as evidence.
- Journald field availability depends on permissions and source service.
- auditd serial assembly waits up to `assembly_timeout` for a completed group. Missing records are retained as explicitly partial evidence; cross-host correlation is out of scope.
- Windows kernel-level ETW and production Linux response adapters remain separate milestones.
