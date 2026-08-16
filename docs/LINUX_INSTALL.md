# Linux installation and upgrade

## Supported baseline

- Debian 12 / Ubuntu 22.04+ or an RPM/systemd distribution with equivalent kernel features;
- Linux kernel 5.8+ and BTF for the optional CO-RE sensor;
- `auditd`, journald access, nftables, POSIX ACL tools, and CA certificates;
- packages verified by the distribution repository signature chain.

Install the signed Debian/RPM package, copy the issued mTLS certificate chain and Agent identity into `/var/lib/ntagentshield`, and edit `/etc/ntagentshield/agent.json`. Keep `privilege_separation.enabled=true`. Never run the Core as root or add `CAP_SYS_ADMIN` to work around an unsupported sensor.

## Host-specific syslog01 compatibility forwarding

The deployment artifact at `packaging/rsyslog/60-ntagentshield-syslog01-forward.conf` forwards conventional host syslog to the syslog01 receiver at `203.113.71.211:5701/UDP` in RFC 5424 format. It is intentionally not installed by the Agent package: copying it to `/etc/rsyslog.d/` is an explicit host deployment decision.

This compatibility path forwards every message received by rsyslog, including authentication and Agent service messages. UDP provides no delivery acknowledgement, peer authentication, encryption, or integrity protection. Use it only when the receiver is on the same host or a trusted protected network. It does not replace the Agent's redacted HTTPS/mTLS transport and does not read or forward `evidence.journal.jsonl`.

Validate and activate it with fixed administrative operations:

```text
rsyslogd -N1
systemctl restart rsyslog.service
```

Build source packages only in a trusted build environment with Go 1.24 or newer:

```text
cd agent
dpkg-buildpackage -us -uc -b
# or use the distribution RPM builder with packaging/rpm/ntagentshield-agent.spec
```

After verifying the package/repository signature, install with the distribution package manager (`apt install ./ntagentshield-agent_*.deb` or `dnf install ./ntagentshield-agent-*.rpm`). The package lifecycle creates the three non-login identities and required ACLs; do not replace them with root.

Run `ntagentshield-doctor --config /etc/ntagentshield/agent.json` before enabling services. Then use `systemctl enable --now ntagentshield-sensor.service ntagentshield-response.service ntagentshield-agent.service`. Sensor failure is visible in health and falls back only to configured auditd/journald collectors; it does not start a shell.

Package upgrades preserve the configuration and local policy. Verify the repository/package signature before upgrade, review configuration changes, run doctor, then restart helpers before Core. Uninstall stops/disables services and deliberately retains `/var/lib/ntagentshield` and `/var/lib/ntagentshield-response` for forensic recovery. Debian purge removes configuration but not forensic state.

The response trust root is pinned under `/var/lib/ntagentshield/trust`. That directory is setgid to `ntagentshield-ipc`: Core can create the public pin and the response helper can read it, but the response helper cannot replace it. Its private ledger/containment signing identity lives separately under `/var/lib/ntagentshield-response`.
