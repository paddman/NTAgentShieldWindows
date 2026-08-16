#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$PackageDir = "",
    [string]$InstallDir = "$env:ProgramFiles\NTAgentShield",
    [string]$DataDir = "$env:ProgramData\NTAgentShield",
    [switch]$ForceConfig
)

$ErrorActionPreference = "Stop"
$TaskName = "NTAgentShield"
if (-not $PackageDir) { $PackageDir = $PSScriptRoot }
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$AgentSource = Join-Path $PackageDir "ntagentshield-agent-windows-amd64.exe"
$CtlSource = Join-Path $PackageDir "ntagentshieldctl-windows-amd64.exe"
$InventorySource = Join-Path $PackageDir "ntagentshield-inventory-windows-amd64.exe"
$EnrollSource = Join-Path $PackageDir "ntagentshield-enroll-windows-amd64.exe"
$ConfigSource = Join-Path $PackageDir "config\windows.example.json"
$PolicySource = Join-Path $PackageDir "policies\default-policy.json"
$YaraSource = Join-Path $PackageDir "yr.exe"
$RulesSource = Join-Path $PackageDir "rules\default.yar"
$RulesManifestSource = Join-Path $PackageDir "rules\default.manifest.json"
$AppSource = Join-Path $PackageDir "NTAgentShield.App.exe"

foreach ($required in @($AgentSource, $ConfigSource, $PolicySource, $YaraSource, $RulesSource, $RulesManifestSource)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Package file is missing: $required"
    }
}

$service = Get-CimInstance Win32_Service -Filter "Name='NTAgentShield'" -ErrorAction SilentlyContinue
if ($service) {
    $ownedService = $service.PathName -match "(?i)NTAgentShield|ntagentshield-agent"
    if (-not $ownedService) { throw "A different service already uses the name NTAgentShield." }
    Stop-Service -Name $TaskName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $TaskName | Out-Null
    Start-Sleep -Seconds 2
}

$oldTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($oldTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

    $oldAgentPath = Join-Path $InstallDir "ntagentshield-agent.exe"
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $oldProcess = Get-Process -Name "ntagentshield-agent" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $oldAgentPath }
        if ($oldProcess) { Start-Sleep -Seconds 1 }
    } while ($oldProcess -and (Get-Date) -lt $deadline)
    if ($oldProcess) {
        $oldProcess | Stop-Process -Force
        Start-Sleep -Seconds 2
    }
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, (Join-Path $InstallDir "policies"), (Join-Path $InstallDir "rules"), (Join-Path $InstallDir "licenses") | Out-Null
$appTarget = Join-Path $InstallDir "NTAgentShield.App.exe"
$appProcess = Get-Process -Name "NTAgentShield.App" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $appTarget }
if ($appProcess) {
    $appProcess | Stop-Process -Force
    Start-Sleep -Seconds 2
}
Copy-Item -LiteralPath $AgentSource -Destination (Join-Path $InstallDir "ntagentshield-agent.exe") -Force
Copy-Item -LiteralPath $YaraSource -Destination (Join-Path $InstallDir "yr.exe") -Force
Copy-Item -LiteralPath $RulesSource -Destination (Join-Path $InstallDir "rules\default.yar") -Force
Copy-Item -LiteralPath $RulesManifestSource -Destination (Join-Path $InstallDir "rules\default.manifest.json") -Force
if (Test-Path -LiteralPath (Join-Path $PackageDir "licenses\YARA-X-LICENSE.txt")) {
    Copy-Item -LiteralPath (Join-Path $PackageDir "licenses\YARA-X-LICENSE.txt") -Destination (Join-Path $InstallDir "licenses\YARA-X-LICENSE.txt") -Force
}
foreach ($optional in @(
    @{ Source = $CtlSource; Name = "ntagentshieldctl.exe" },
    @{ Source = $InventorySource; Name = "ntagentshield-inventory.exe" },
    @{ Source = $EnrollSource; Name = "ntagentshield-enroll.exe" }
)) {
    if (Test-Path -LiteralPath $optional.Source -PathType Leaf) {
        Copy-Item -LiteralPath $optional.Source -Destination (Join-Path $InstallDir $optional.Name) -Force
    }
}
if (Test-Path -LiteralPath $AppSource -PathType Leaf) {
    Copy-Item -LiteralPath $AppSource -Destination $appTarget -Force
    $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
    New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
    $shortcutPath = Join-Path $startMenu "NTAgentShield.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $appTarget
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.IconLocation = "$appTarget,0"
    $shortcut.Description = "NTAgentShield Windows dashboard"
    $shortcut.Save()
}

$policyTarget = Join-Path $InstallDir "policies\default-policy.json"
if (-not (Test-Path -LiteralPath $policyTarget)) {
    Copy-Item -LiteralPath $PolicySource -Destination $policyTarget -Force
}
$configTarget = Join-Path $DataDir "agent.json"
if ($ForceConfig -or -not (Test-Path -LiteralPath $configTarget)) {
    Copy-Item -LiteralPath $ConfigSource -Destination $configTarget -Force
} else {
    # Add newly introduced protection sections without replacing tenant,
    # enrollment, transport, source, or operator-customized settings.
    $currentConfig = Get-Content -LiteralPath $configTarget -Raw | ConvertFrom-Json
    $packageConfig = Get-Content -LiteralPath $ConfigSource -Raw | ConvertFrom-Json
    foreach ($section in @('protection', 'scanner', 'reputation', 'retention')) {
        if (-not $currentConfig.PSObject.Properties[$section]) {
            $currentConfig | Add-Member -NotePropertyName $section -NotePropertyValue $packageConfig.$section
        }
    }
    $defenderSource = $packageConfig.native_sources | Where-Object { $_.id -eq 'windows-defender-operational' }
    if ($defenderSource -and -not ($currentConfig.native_sources | Where-Object { $_.id -eq 'windows-defender-operational' })) {
        $currentConfig.native_sources = @($currentConfig.native_sources) + @($defenderSource)
    }
    $mergedConfig = $currentConfig | ConvertTo-Json -Depth 32
    [IO.File]::WriteAllText($configTarget, $mergedConfig + [Environment]::NewLine, (New-Object Text.UTF8Encoding($false)))
}

# Capture native process creation telemetry used by the user-mode EDR sensor.
# This augments Microsoft Defender; it never disables or replaces Defender.
try {
    & auditpol.exe /set '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE" }
    $auditKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    New-Item -Path $auditKey -Force | Out-Null
    New-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
} catch {
    Write-Warning "Could not enable Security 4688 process telemetry: $($_.Exception.Message)"
}
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    if (-not $defender.AntivirusEnabled -or -not $defender.RealTimeProtectionEnabled) {
        Write-Warning "Microsoft Defender real-time protection is not fully enabled. NTAgentShield is designed to coexist with Defender."
    }
} catch {
    Write-Warning "Microsoft Defender status could not be read: $($_.Exception.Message)"
}

# Keep config, enrollment material, API token, and evidence private to SYSTEM and Administrators.
& icacls.exe $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to secure data directory ACLs: $DataDir" }

$agentPath = Join-Path $InstallDir "ntagentshield-agent.exe"
$argument = '--config "{0}"' -f $configTarget
$action = New-ScheduledTaskAction -Execute $agentPath -Argument $argument -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "NTAgentShield endpoint security agent." | Out-Null
Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddSeconds(30)
do {
    Start-Sleep -Seconds 1
    $running = Get-Process -Name "ntagentshield-agent" -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $agentPath }
} while (-not $running -and (Get-Date) -lt $deadline)

if (-not $running) {
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    throw "NTAgentShield did not start. LastTaskResult=$($info.LastTaskResult)"
}

Write-Host "NTAgentShield installed and running."
Write-Host "Task       : $TaskName (SYSTEM, at startup)"
Write-Host "Binary     : $agentPath"
Write-Host "Config     : $configTarget"
Write-Host "Data       : $DataDir"
if (Test-Path -LiteralPath $appTarget) { Write-Host "App        : $appTarget (Start Menu shortcut created)" }
