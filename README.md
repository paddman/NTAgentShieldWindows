# NTAgentShield Windows

NTAgentShield Windows is an open-source endpoint agent for Windows detection,
investigation, and bounded malware protection. It combines native Windows
telemetry, deterministic behavioral rules, a tamper-evident evidence journal,
YARA-X, AMSI, Microsoft Defender events, inventory, and a local dashboard.

The agent can connect to NTAgentShield Central over HTTPS, register with a
short-lived enrollment token, send authenticated heartbeats, and forward
redacted events and findings. Response actions remain typed and policy-gated;
telemetry or AI output cannot directly execute a shell command.

## Current capabilities

- Windows Security, System, PowerShell, Defender, Sysmon, and multi-site IIS W3C collectors
- Process, authentication, persistence, network, and defense-evasion rules
- YARA-X and AMSI-backed file verdicts
- Scheduled quick and full malware scans
- Seven-day audit period before enforcement is eligible
- Reversible quarantine and bounded process termination
- Ed25519-signed YARA rule manifest verification
- Tamper-evident JSONL evidence journal with retention limits
- Authenticated loopback status/scan API and Windows desktop dashboard
- NTAgentShield Central registration, heartbeat, and event forwarding

## Safety model

The default Windows configuration starts protection in `audit` mode. Changing
to `enforce` is an explicit administrator decision after reviewing audit
findings. Host isolation, process termination, quarantine, and firewall actions
must pass deterministic policy and approval checks. Arbitrary shell execution
is denied.

## Build from source

Requirements:

- Go 1.24 or newer
- PowerShell 5.1 or newer
- .NET 10 SDK for the optional desktop dashboard package
- A verified YARA-X `yr.exe` binary when building the complete installer

```powershell
go test ./...
go build -trimpath -o ntagentshield-agent.exe ./cmd/ntagentshield-agent
go build -trimpath -o ntagentshieldctl.exe ./cmd/ntagentshieldctl
```

To assemble the Windows package:

```powershell
.\packaging\windows\build-package.ps1 `
  -Version 0.2.3-windows.audit `
  -YaraXExe C:\path\to\verified\yr.exe
```

## Install

Extract the generated package, open PowerShell as Administrator, and run:

```powershell
.\install.ps1
```

The installer places binaries under `C:\Program Files\NTAgentShield`, keeps
configuration and evidence under `C:\ProgramData\NTAgentShield`, and runs the
agent as `SYSTEM` through the `NTAgentShield` Scheduled Task.

See [Windows packaging](packaging/windows/README.md),
[architecture](docs/ARCHITECTURE.md), [response safety](docs/RESPONSE_SAFETY.md),
and [security policy](SECURITY.md) for operational details.

## Central connection

Add a `central` object to `C:\ProgramData\NTAgentShield\agent.json`. Never
commit enrollment tokens or agent API keys to source control.

```json
{
  "tenant_id": "your-tenant",
  "central": {
    "enabled": true,
    "url": "https://central.example.com",
    "enrollment_token_file": "C:\\ProgramData\\NTAgentShield\\central-enrollment.token",
    "api_key_file": "central-api.key",
    "allow_untrusted_server_certificate": false,
    "heartbeat_interval": "60s",
    "batch_interval": "10s",
    "max_batch": 100,
    "queue_size": 10000
  }
}
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
