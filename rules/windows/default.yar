import "pe"

rule NTAS_EICAR_Test_File : test malware
{
  meta:
    author = "NTAgentShield"
    severity = "critical"
    action = "block"
    description = "Standard EICAR anti-malware test file"
  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
  condition:
    $eicar
}

rule NTAS_Mimikatz_High_Confidence : credential_access malware
{
  meta:
    author = "NTAgentShield"
    severity = "critical"
    action = "block"
    description = "Multiple high-confidence Mimikatz command and module markers"
  strings:
    $module = "sekurlsa" ascii wide nocase
    $command1 = "logonpasswords" ascii wide nocase
    $command2 = "lsadump::sam" ascii wide nocase
    $command3 = "kerberos::golden" ascii wide nocase
  condition:
    $module and 1 of ($command*)
}

rule NTAS_Suspicious_PE_Overlay_Packer : suspicious packed
{
  meta:
    author = "NTAgentShield"
    severity = "medium"
    action = "alert"
    description = "PE with several common packer markers; alert-only contextual rule"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
    $mpress = ".MPRESS" ascii nocase
  condition:
    uint16(0) == 0x5a4d and 2 of them
}
