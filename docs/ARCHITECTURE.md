# Architecture

## Current foundation

```text
+---------------- Server / Endpoint ----------------+
|                                                   |
| Log files / normalized sensor events / code       |
|                 |                                 |
|                 v                                 |
|        Collector + format parser                  |
|                 |                                 |
|                 v                                 |
|          Redaction + provenance                   |
|             /             \                       |
|            v               v                      |
|  Hash-chain journal   Detection engine            |
|                            |                      |
|                            v                      |
|                         Finding                   |
|                         /     \                   |
|                        v       v                  |
|              Read-only AI   Policy engine         |
|              no tools       typed tools only      |
|                                                   |
+---------------------------------------------------+
```

## Components

### Agent runtime

The runtime loads configuration, creates a stable local identity, opens the evidence journal, initializes collectors, starts the loopback API, processes events, and records findings. It runs without third-party runtime dependencies.

### Collectors and parsers

The foundation tails bounded log increments and supports IIS W3C, Nginx combined, MySQL general, Syslog, normalized JSON, and raw text. Future native sensors will produce the same normalized event model.

On Linux, the auditd collector assembles related records by audit serial before normalization. It retains only bounded active groups, hashes each raw record instead of copying it into evidence, emits explicit partial groups on timeout/capacity/rotation, and separates its read watermark from its durable cursor. This preserves at-least-once delivery: the cursor advances only after the assembled event and any deterministic findings are journaled.

The Linux process graph periodically reconciles bounded `/proc` observations. A process identity is deterministic over `boot_id_hash`, PID, and `/proc/<pid>/stat` start ticks, so a reused PID is a new node. Graph checkpoints advance only after recovered process start/exit evidence is journaled; incomplete or capped scans do not infer exits. The graph has no response authority and only enriches telemetry with a matching current process identity.

The Linux process-aware network inventory reads the fixed `/proc/net/{tcp,tcp6,udp,udp6}` tables and `/proc/<pid>/fd` links directly. It joins socket inodes only to an active process graph node with an exact PID/start-ticks match, then emits bounded `network.listen` or `network.connection` evidence. Its in-memory known-socket set is advanced only after evidence and findings are journaled. Missing permissions, disappearing processes, and PID reuse leave ownership unresolved rather than guessed.

The Linux eBPF module embeds one reviewed CO-RE object with a fixed tracepoint allowlist. The unprivileged core receives ring-buffer records, rate-limits normalization, resolves a process only through the boot-time/PID graph identity, redacts before persistence, and sends the resulting evidence through the normal journal/detection path. The module has no control plane for BPF source, filters, attach points, commands, or response. A failed BTF/capability/load/attach check leaves the sensor disabled and records a health fallback reason; auditd/journald remain the only fallback telemetry sources.

On hardened Linux deployments, three dedicated identities enforce the privilege boundary. `ntagentshield-agent` owns evidence, detection, redaction, mTLS, and outbox handling with an empty capability set. `ntagentshield-sensor` owns only the fixed embedded eBPF loader and a bounded telemetry queue. `ntagentshield-response` owns only signed typed response execution. Each helper listens in its own service-owned runtime directory and accepts only the configured Core UID verified from kernel `SO_PEERCRED` credentials.

The local protocol is length-prefixed strict JSON with a fixed version, cryptographic request ID, method allowlist, issuance time, maximum message size, deadline, bounded replay cache, and metadata-only audit record. Sensor batches remain untrusted telemetry and are replayed until Core acknowledges them after event and finding journal writes. Response IPC carries the original signed lease—not a command—and the helper independently repeats Ed25519 verification, tenant/agent binding, action digest construction, local signed-policy evaluation, typed argument validation, and crash-safe ledger checks.

### Redaction

Redaction occurs before persistence and before AI transfer. It handles bearer tokens, common secret assignments, private keys, payment-number patterns, and nested secret-like fields. Redaction is defense in depth, not a substitute for collecting the minimum necessary fields.

### Evidence journal

Each JSONL record contains sequence, timestamp, type, previous hash, payload hash, and record hash. Verification detects modification, deletion within the chain, insertion, and reordering. The foundation journal is tamper-evident, not tamper-proof; production will anchor checkpoints to the control plane or a trusted signing service.

### Detection engine

Detections are deterministic and evidence-backed. Stateful correlation includes authentication bursts plus Linux file-drop-to-execution and mass-file-modification sequences. Linux correlation is offline and bounded: 2,048 drop paths for 10 minutes, and 1,024 process identities with at most 128 paths each in a 60-second window. Oldest-time/lexical eviction makes capacity behavior reproducible. Findings carry bilingual explanations, MITRE mappings, evidence/process context, investigation steps, and a typed response recommendation; the recommendation has no execution authority. Planned engines add Sigma conversion, YARA/YARA-X, broader ETW behavior sequences, per-asset baselines, and cross-host graphs.

### Code scanner

The current scanner is a bounded lexical layer with secret-safe excerpts. Planned adapters add Tree-sitter data flow, Semgrep, SBOM/dependency analysis, IaC scanners, and sandboxed patch validation.

### AI investigator

The AI client speaks to an OpenAI-compatible endpoint. It receives redacted evidence enclosed as untrusted JSON, receives no tools, and returns analysis only. The model is not an authorization authority and its confidence does not trigger response.

### Policy and tools

Tools declare canonical risk. The policy denies generic command tools, caps action TTL, blocks destructive actions in the foundation, and prevents untrusted evidence from directly causing state changes. Read-only file tools resolve symlinks and enforce configured roots.

### Local API

The local API binds to loopback, uses a generated bearer token, and exposes only health, status, and event ingestion. Remote event payloads are forcibly marked `untrusted_network`. No command or tool endpoint exists.

## Linux typed response boundary

Linux state-changing response runs only in the separate restricted helper:

```text
Unprivileged Agent / Investigator
              |
       signed typed request
              v
Deterministic Policy Gate
              |
   exact approval / pre-policy
              v
Privileged Response Broker
              |
    bounded Linux adapter
              v
Verify outcome + append audit + rollback
```

The helper supports only `process.terminate`, `process.terminate_tree`, `host.isolate`/release, exact IP block/unblock, typed port open/close, and allowlisted file quarantine/restore. Process actions bind PID to `/proc` start ticks to reject PID reuse. nftables actions modify only signed NTAgentShield-owned tables through fixed arguments and verify kernel state after each change. Quarantine objects and manifests are SHA-256 verified and locally signed. The investigator remains unprivileged and has no path to this helper; every request must be an approved, short-lived, tenant/agent-bound signed lease.

Private response identity, crash-safe ledger, quarantine objects, and containment ownership live under `/var/lib/ntagentshield-response`. The response helper has read-only traversal to the Core-owned public signing pin under `/var/lib/ntagentshield/trust`, but cannot replace it.

## Control-plane integration

Planned NT Shield integration includes:

- mTLS enrollment and short-lived workload identity;
- tenant-scoped policy and rule distribution;
- central incident correlation and evidence graph;
- local/central Qwen model routing;
- signed update manifests and staged rollout;
- audit, retention, reporting, and usage accounting;
- air-gapped deployment mode;
- strict tenant partitioning with platform-admin oversight.

## Event compatibility

The internal event schema is intentionally compact. A control-plane adapter will map it to OCSF classes and export via OTLP where appropriate. Security meaning and telemetry transport remain separate concerns.
