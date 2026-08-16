# Linux identities, permissions, and capabilities

Production Linux installs use three dedicated, non-login users and one connect-only group:

| Identity | Purpose | Capabilities |
|---|---|---|
| `ntagentshield-agent` | evidence journal, offline detection, redaction, mTLS/outbox | none |
| `ntagentshield-sensor` | fixed embedded CO-RE telemetry only | `CAP_BPF`, `CAP_PERFMON` |
| `ntagentshield-response` | signed typed containment only | `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` |
| `ntagentshield-ipc` | lets the Core connect to helper-owned sockets | no capabilities |

The Core is a supplementary member of `ntagentshield-ipc`. Each helper uses that group for its `0660` socket but owns a distinct `0750` runtime directory. The server validates the Core's exact UID through `SO_PEERCRED`; group membership alone is not accepted by the shipped units.

Configuration and policy under `/etc/ntagentshield` are read-only to services. Core evidence, outbox, certificates, and identity state live under `/var/lib/ntagentshield`. Public response trust is pinned in its setgid `trust/` subdirectory. Private response ledger, quarantine, containment ownership, and local signing state live under `/var/lib/ntagentshield-response`; the helper can modify only that state plus quarantine paths explicitly listed by local configuration. The sensor's process-context checkpoint is ephemeral under `/run/ntagentshield-sensor`.

Do not add `CAP_SYS_ADMIN` merely to make an unsupported kernel load eBPF. Kernel 5.8+, BTF, `CAP_BPF`, and `CAP_PERFMON` are the supported path; otherwise auditd/journald remain active and sensor health records the fallback reason. Do not run the Core as root.

On distributions that mount tracefs as `0700 root:root`, the fixed one-shot `ntagentshield-tracefs.service` remounts that API filesystem as `gid=ntagentshield-sensor,mode=0750`. The short-lived provisioning process has only `CAP_SYS_ADMIN` and exits after the exact remount; the long-running Sensor keeps only `CAP_BPF` and `CAP_PERFMON`. Tracepoint ID files become group-readable while trace configuration files remain non-writable.

The shipped systemd units keep `NoNewPrivileges`, strict filesystem protection, private temporary/device views, kernel/control-group protections, capability bounding sets, and restricted address families. If a local quarantine allowlist expands beyond the shipped writable paths, update both the signed local policy and the response unit's `ReadWritePaths`; never replace them with a broad writable root.
