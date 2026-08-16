# NTAgentShield Windows package

This package installs the Go endpoint agent on Windows amd64.

## Build

Build requirements: Go 1.24 or later, the .NET 10 SDK, and the verified
YARA-X `yr.exe` v1.19.0 release binary.

From the `agent` directory in an elevated or normal PowerShell session:

```powershell
.\packaging\windows\build-package.ps1 -Version 0.2.1-windows.audit -YaraXExe C:\path\to\yr.exe
```

The package is written to `dist\windows\ntagentshield-windows-amd64-<version>.zip`.

## Install

Extract the zip, open PowerShell as Administrator, and run:

```powershell
.\install.ps1
```

The installer:

- installs the binaries under `C:\Program Files\NTAgentShield`;
- installs the `NTAgentShield.App.exe` Windows dashboard and a Start Menu shortcut;
- creates the first configuration at `C:\ProgramData\NTAgentShield\agent.json`;
- preserves an existing configuration and evidence directory during upgrades;
- runs the agent as `SYSTEM` through the `NTAgentShield` Scheduled Task at startup;
- restarts the task up to three times after an unexpected exit; and
- restricts the data directory to `SYSTEM` and local Administrators;
- installs YARA-X plus an Ed25519-signed rules manifest;
- enables Windows Security 4688 process telemetry where local policy permits;
- collects Microsoft Defender Operational events; and
- starts NGAV in a seven-day `audit` period before enforcement is eligible.

The current Go executable is a console process, so the package uses a Scheduled Task rather than registering it directly with the Windows Service Control Manager.

Launch `NTAgentShield.App.exe` from the Start Menu for a local dashboard. The app polls `127.0.0.1:9477`, shows Agent and protection health, and can start a bounded quick malware scan. The authenticated loopback API exposes status plus this one typed scan action; it does not expose a shell or arbitrary tool execution. The app requests Administrator elevation because task control, the API token, and the protected evidence journal are privileged.

```powershell
ntagentshieldctl.exe protection-status --config C:\ProgramData\NTAgentShield\agent.json
ntagentshieldctl.exe protection-scan --config C:\ProgramData\NTAgentShield\agent.json --profile quick
```

After reviewing audit findings for at least seven days, an administrator may
change `protection.mode` in `agent.json` from `audit` to `enforce` and restart
the task. Enforcement remains bounded to verified process termination and
signed, reversible file quarantine. Host/network isolation still requires an
approved response action.

To intentionally replace the existing configuration:

```powershell
.\install.ps1 -ForceConfig
```

## Uninstall

```powershell
.\uninstall-service.ps1 -RemoveFiles
```

Configuration and evidence remain under `C:\ProgramData\NTAgentShield` unless `-RemoveData` is supplied.
