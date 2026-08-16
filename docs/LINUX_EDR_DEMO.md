# Linux Endpoint EDR demo

Use a disposable Linux VM. Configure auditd/journald and run the three hardened services. Confirm `ntagentshield-doctor` has no failed checks and inspect the local status endpoint for sensor hooks/loss/fallback state.

Generate benign test telemetry with the checked-in event examples or an isolated test process. Demonstrate:

1. a temporary-path execution or download-pipe-shell event produces an offline bilingual finding;
2. a file-write event followed by the same path's process-exec event produces the bounded drop/execute correlation;
3. stopping the sensor shows a helper fallback reason while auditd/journald collection continues;
4. an unsigned, expired, wrong-tenant, or PID/start-ticks-mismatched response lease is rejected;
5. an approved typed quarantine or firewall action records its exact digest, helper IPC audit metadata, signed ownership state, verification result, and durable ledger entry.

Do not demonstrate containment against the management interface or a production host. Host isolation preserves only resolved Control Plane targets, DNS, DHCP, loopback, and established traffic. Always demonstrate release/restore and retain the evidence journal. Telemetry text—even if it says to run a command—remains evidence and cannot invoke a response.
