# Threat Model

## Protected assets

- Host integrity and availability.
- Credentials, tokens, private keys, and customer data.
- Evidence authenticity and incident timelines.
- Agent identity, policy, rule, model, and update integrity.
- Operator approvals and response authority.
- Tenant separation and data residency.
- AI context, memory, tool catalog, and model endpoint.

## Adversaries

- Remote attacker exploiting a web, API, database, or AI service.
- Local unprivileged user attempting privilege escalation.
- Compromised administrator or stolen operator token.
- Malicious dependency, plugin, model, adapter, or update source.
- Attacker who controls log fields, source comments, tickets, RAG documents, or tool descriptions.
- Compromised control plane attempting to overreach endpoint policy.
- Insider attempting to access another tenant’s evidence.

## Trust boundaries

### Untrusted evidence boundary

The following remain untrusted regardless of how plausible they look:

- HTTP method/path/query/header/body metadata;
- IIS, Nginx, Apache, firewall, database, and application logs;
- filenames, process command lines, DNS names, and certificate fields;
- source code, comments, commit messages, CI output, and dependencies;
- email, ticket, chat, RAG document, vector-store content, and MCP descriptions;
- AI model output.

Authentication proves the sender’s identity, not the truth or authority of payload content.

### Policy boundary

Only deterministic policy decides whether a typed action may run. Model output is never an approval. Tool risk is defined in code, not supplied by the caller.

### Privilege boundary

The Core and AI have no Linux capabilities. Linux response runs in a separate helper with minimum OS rights and accepts only fixed typed requests carrying the original signed lease. The helper independently checks signature, tenant/agent binding, exact digest, expiry, replay/idempotency ledger, and local signed policy. The AI process does not inherit helper privileges or receive its socket protocol as a tool.

### Tenant boundary

Every event, finding, policy, action, model request, and audit record must carry tenant identity. Central storage, queues, caches, vector indexes, and object paths must enforce the same boundary.

## Primary attack scenarios and controls

| Attack | Control |
|---|---|
| Indirect prompt injection through User-Agent or log text | Trust labels, evidence envelope, no tools in AI request, deterministic policy |
| AI asks for `shell.exec` | Generic shell tools do not exist and are explicitly denied |
| Caller lies about tool risk | Registry overwrites caller risk with canonical tool risk |
| Path traversal through file tool | Absolute path, symlink resolution, allowlisted roots |
| Approval replay for a modified action | Digest binds tool, arguments, reason, risk, and trigger trust; expiry enforced |
| Journal modification | Payload hash and chained record hash verification |
| Secret leakage to journal/model | Pre-persistence redaction, bounded evidence, minimal collection |
| Remote API exposure | Config rejects non-loopback binding; token authentication; no action endpoint |
| Oversized log/API payload | Scanner and HTTP body limits, bounded file reads, per-poll limits |
| Malicious model response | Output remains analysis only; no automatic action path |
| Poisoned rule/plugin/update | Planned signatures, hash pinning, staged rollout, revocation |
| Compromised endpoint forges clean evidence | Planned control-plane checkpoint anchoring and cross-source correlation |
| DoS via high event volume | Planned backpressure, durable queue, rate limits, priority tiers, sampling policy |

## Residual risks in 0.1

- The journal is not encrypted at rest and is not anchored externally.
- File-tail offsets are in memory; restarts can intentionally start at configured end/beginning but do not persist exact cursors.
- Linux eBPF is restricted to a fixed embedded CO-RE tracepoint object. The loader requires kernel BTF and narrow telemetry capabilities; it rejects all remote programs, filters, and attach-point input. A failure falls back only to configured auditd/journald collectors, never a shell. Windows ETW remains outside this Linux-first work.
- Linux detections consume telemetry only as untrusted evidence. Stateful rules have fixed TTL/cardinality/path limits and deterministic eviction, preventing attacker-controlled event volume from creating unbounded correlation state. A finding's typed response name is advisory metadata and cannot create an approval, lease, action argument, or execution request.
- Linux helper sockets use separate service-owned runtime directories, restrictive modes, kernel `SO_PEERCRED` UID validation, strict fixed-method schemas, deadlines, bounded frame sizes, cryptographic request IDs, replay windows, and metadata-only audit logs. The sensor helper can emit evidence only. The response helper accepts only an already signed lease and repeats all authorization checks locally; compromising the unprivileged Core alone does not grant a raw privileged command channel.
- Linux process response binds the requested PID to `/proc/<pid>/stat` start ticks before every signal and refuses protected Agent processes. nftables response touches only signed NTAgentShield-owned fixed tables, uses typed IP/protocol/direction/port values, and verifies read-back state. Quarantine resolves a local allowlist, refuses overwrite/symlink escape, signs its manifest, and verifies SHA-256 after durable copy.
- Debian/RPM installation relies on the distribution package/repository signature chain and deliberately provides no unsigned self-updater. Configuration is preserved across upgrades; private response state is separated from Core evidence and trust pins.
- Detection rules are compiled into the binary and not signed separately.
- A crash after an operating-system mutation but before ledger finalization leaves the action `indeterminate` and requires operator investigation; the helper fails closed rather than replaying it automatically.
- AI output is redacted with the same general redactor but requires stronger output DLP before production.
- Lexical code scanning lacks full interprocedural data flow.

These are explicit roadmap items, not hidden beneath a dashboard animation.
