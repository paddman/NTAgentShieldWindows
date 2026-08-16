# Roadmap

## PR 0: Product boundary and threat model

Status: **implemented in foundation**

- product definition;
- architecture and trust boundaries;
- AI security and response-safety model;
- language and no-generic-shell ADRs.

## PR 1: Secure agent core

Status: **foundation implemented**

- stable local identity;
- configuration validation;
- loopback API and token;
- evidence journal;
- policy engine;
- typed read-only tools;
- CI and cross-platform builds.

## PR 2: Native asset inventory and endpoint telemetry

Status: **Linux CO-RE eBPF, offline detection pack, three-process privilege separation, typed response, and packaging foundation implemented; remaining collectors planned**

- Windows Event Log and Sysmon collectors;
- Linux journald and auditd collectors;
- process, service, package, listening-port, user, and persistence inventory;
- durable collector cursors and backpressure;
- resource-budget telemetry.
- bounded Linux drop/execute and mass-file-modification behavior correlation;
- bilingual Linux findings with MITRE and typed-response investigation guidance.

## PR 3: Web, database, firewall, and container collectors

- production IIS/Nginx/Apache adapters;
- PostgreSQL and SQL Server audit adapters;
- database query fingerprint/redaction policy;
- firewall/WAF vendor parsers;
- Docker/Podman/Kubernetes telemetry.

## PR 4: Detection fabric

- external signed rule packs;
- Sigma conversion;
- YARA/YARA-X and Suricata adapters;
- temporal behavior DSL;
- per-role baselines and anomaly scoring;
- ATT&CK/ATLAS mapping and test corpus.

## PR 5: Code-security workspace

Foundation lexical scanner exists. Planned:

- Tree-sitter AST and data flow;
- Semgrep adapter;
- SBOM, dependency, secret, IaC, container, and CI scanners;
- repository indexing and incremental scan;
- security diff, patch proposal, sandbox tests, checkpoint and rollback.

## PR 6: Cline-style security console

- desktop console and terminal TUI;
- Observe/Plan/Act modes;
- evidence timeline and graph;
- tool-call preview;
- diff review and approval;
- incident notebooks and export.

## PR 7: AI investigator and AI runtime guard

Foundation read-only AI client exists. Planned:

- central/local model routing;
- structured evidence citations;
- output DLP and canary-secret detection;
- RAG provenance and poisoning controls;
- MCP/tool manifest signatures;
- memory-write policy;
- Thai/English injection red-team suite.

## PR 8: Privileged response broker

Status: **Linux foundation implemented; Windows response remains outside the Linux-first change set**

- separate Linux service identity and narrow capability bounding set;
- signed typed Linux process, nftables, isolation, and quarantine adapters;
- exact approval, local signed-policy recheck, crash-safe ledger, verification, and supported rollback;
- Debian/RPM foundations, hardened systemd units, and read-only Linux doctor;
- planned: emergency kill switch, global action budget, and optional privileged distribution integration tests.

## PR 9: Unknown-threat hunter

- web-request-to-process-to-file-to-network chains;
- database-to-process/file correlation;
- rare parent-child and destination behavior;
- exploit primitive and post-exploitation detections;
- virtual WAF patch proposal.

## PR 10: NT Shield control-plane integration

- mTLS enrollment and rotation;
- tenant-scoped fleet and policy;
- central evidence graph and incidents;
- Qwen inference on NT infrastructure;
- signed rule/model/update distribution;
- reporting, SLA, retention, billing, and air-gap mode.
