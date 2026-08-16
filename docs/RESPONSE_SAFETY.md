# Response Safety

## Risk classes

| Risk | Examples | Foundation behavior |
|---|---|---|
| Observe | host info, file metadata/hash, bounded file lines | may auto-allow by policy |
| Contain | isolate host, block IP/port, terminate process, quarantine file | exact approval required; typed Linux adapters implemented |
| Modify | change config, temporary WAF rule, disable account | approval required; adapters not implemented |
| Destructive | delete file, wipe data, irreversible kill chain | denied by foundation policy |

## Required action lifecycle

Every state-changing tool must implement:

1. Typed input schema.
2. Canonical risk defined by the tool.
3. Resource scope and allowlist.
4. Preconditions and expected current state.
5. Dry-run output where the adapter supports a faithful preview.
6. Exact-action digest.
7. Role and tenant authorization.
8. Approval or signed pre-policy.
9. Timeout and action budget.
10. Evidence snapshot before execution.
11. Idempotent execution where possible.
12. Outcome verification.
13. Audit append.
14. Rollback or explicit irreversibility notice.

## Approval binding

The foundation digest includes:

- tool name;
- full argument object;
- reason;
- canonical risk;
- trigger trust.

Changing any of these invalidates the approval. Approvals expire and require a named approver.

## Untrusted-trigger rule

Untrusted telemetry may justify a finding and a proposed plan. It cannot directly trigger a state-changing tool. An operator or signed deterministic incident policy must independently authorize the action.

## No generic shell

A generic shell cannot provide bounded scope, predictable side effects, reliable rollback, or meaningful schema validation. It is therefore excluded. New capabilities must be implemented as narrow tools such as:

```text
host.isolate(operation)
process.terminate(pid, expected_start_time_ticks)
process.terminate_tree(pid, expected_start_time_ticks)
file.quarantine(operation, path, expected_sha256)
firewall.block(operation, remote_ip)
firewall.port(operation, protocol, direction, port)
```

## Linux privileged response helper

The Linux Core never executes a state-changing response when privilege separation is enabled. It fetches the exact signed lease over the existing mTLS/Ed25519 transport and passes that bundle to `ntagentshield-response` through the fixed `response.execute` Unix-socket method. Kernel peer credentials must match the configured unprivileged Core UID.

The helper treats the IPC payload as untrusted until it independently verifies the response signer, digest, short lifetime, tenant/agent scope, proposer/approver metadata, and time ordering. It reconstructs the canonical action digest, evaluates the locally signed policy, validates the registered tool's exact typed arguments, and enters the crash-safe ledger before execution. Replayed action IDs return the stored terminal result; indeterminate actions fail closed. IPC cannot supply a tool implementation, shell, executable, free-form argument vector, policy, or approval.

Linux process termination requires both an exact PID and `/proc/<pid>/stat` start ticks. Tree termination discovers at most 4,096 processes, revalidates every PID/start identity, refuses NTAgentShield service processes, terminates descendants before their parent, and verifies exit. Linux firewall port actions accept only typed TCP/UDP, inbound/outbound, port, and open/close values; they operate only on the signed-owned `ntshield_ports` nftables table and read back the resulting set. Quarantine and restore remain restricted to local allowlisted paths and signed manifests.

## Automatic response

Automatic response should begin with evidence-preservation actions, not aggressive containment. Candidate low-risk actions include increasing local telemetry, capturing a process tree, hashing referenced files, and creating a forensic checkpoint. Even these require resource limits and signed policy.
