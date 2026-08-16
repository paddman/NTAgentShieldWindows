package detection

import (
	"regexp"
	"strings"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

type nativeHighSignalRule struct{}

var auditControlDisabled = regexp.MustCompile(`(?i)(?:audit(?:ing)?[_ -]?(?:enabled|status)|enabled)\s*[:=]\s*(?:0|false|no|disabled)|\bauditctl\s+-e\s+0\b|\bdisable(?:d)?\b`)

func (nativeHighSignalRule) ID() string { return "NTS-NATIVE-001" }

func (r nativeHighSignalRule) Evaluate(event model.Event) []model.Finding {
	switch event.Kind {
	case "security.log_clear", "security.log_service_stopped":
		finding := model.NewFinding(event, r.ID(), "Windows security event log was cleared", "Native Windows telemetry reports that an audit log was cleared. This is a high-signal defense-evasion event and requires immediate evidence preservation.", "defense_evasion.log_clear", model.SeverityCritical, 98)
		if event.Kind == "security.log_service_stopped" {
			finding.Title = "Security telemetry service was stopped"
			finding.Description = "Native telemetry reports that a security logging service stopped. This can create a visibility gap and requires immediate verification."
			finding.Category = "defense_evasion.telemetry_disable"
		}
		finding.MITRETactics = []string{"Defense Evasion"}
		finding.MITRETechniques = []string{"T1070.001"}
		finding.RecommendedSteps = []string{"Preserve the local hash-chained journal", "Identify the account and process associated with the clear operation", "Correlate logon, privilege, and remote-access events before the clear timestamp"}
		return []model.Finding{finding}
	case "process.tamper":
		finding := model.NewFinding(event, "NTS-NATIVE-002", "Process tampering detected by native telemetry", "Sysmon or equivalent native telemetry reported process tampering. This can indicate process hollowing, image replacement, or another evasion primitive.", "defense_evasion.process_tamper", model.SeverityCritical, 96)
		finding.MITRETactics = []string{"Defense Evasion", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1055"}
		finding.RecommendedSteps = []string{"Capture the target process metadata and memory if policy permits", "Inspect parent and sibling processes", "Correlate image loads, remote threads, and outbound network activity"}
		return []model.Finding{finding}
	case "process.remote_thread":
		finding := model.NewFinding(event, "NTS-NATIVE-003", "Remote thread creation detected", "Native telemetry reports creation of a thread in another process. This is commonly associated with process injection but can also occur in approved security or management software.", "execution.remote_thread", model.SeverityHigh, 90)
		finding.MITRETactics = []string{"Defense Evasion", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1055"}
		finding.RecommendedSteps = []string{"Validate source and target process signatures", "Check whether the source is an approved security product", "Correlate target-process access and network events"}
		return []model.Finding{finding}
	case "persistence.scheduled_task":
		finding := model.NewFinding(event, "NTS-NATIVE-004", "Scheduled task created or modified", "Native Windows telemetry reports scheduled-task persistence. Treat this as suspicious when it is outside approved deployment or administration activity.", "persistence.scheduled_task", model.SeverityHigh, 86)
		finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1053.005"}
		finding.RecommendedSteps = []string{"Inspect the task action, principal, trigger, and author", "Compare against the approved configuration baseline", "Hash referenced executables or scripts"}
		return []model.Finding{finding}
	case "service.create":
		finding := model.NewFinding(event, "NTS-NATIVE-005", "System service was created", "Native telemetry reports service creation. Services are frequently used for legitimate deployment and for persistence, so correlate the binary path, signer, creator, and change window.", "persistence.service", model.SeverityHigh, 84)
		finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1543.003"}
		finding.RecommendedSteps = []string{"Inspect the service binary path and signature", "Verify the creating account and deployment window", "Check for network or file activity involving the service binary"}
		return []model.Finding{finding}
	case "identity.account_create":
		finding := model.NewFinding(event, "NTS-NATIVE-006", "Local or domain account was created", "Native audit telemetry reports account creation. Validate whether the account, creator, privileges, and timing match an approved identity workflow.", "persistence.account_create", model.SeverityHigh, 82)
		finding.MITRETactics = []string{"Persistence"}
		finding.MITRETechniques = []string{"T1136"}
		finding.RecommendedSteps = []string{"Identify the creator account and source host", "Review group membership changes", "Disable or contain only through an approved response policy"}
		return []model.Finding{finding}
	case "security.audit_config":
		text := eventText(event)
		if auditControlDisabled.MatchString(text) {
			finding := model.NewFinding(event, "NTS-NATIVE-007", "Auditing was disabled or weakened", "Native telemetry indicates that audit policy or enforcement may have been disabled or weakened.", "defense_evasion.audit_disable", model.SeverityCritical, 94)
			finding.MITRETactics = []string{"Defense Evasion"}
			finding.MITRETechniques = []string{"T1562.001"}
			finding.RecommendedSteps = []string{"Preserve the local journal and audit configuration", "Identify the process and account that changed audit settings", "Compare current audit rules with the signed baseline"}
			return []model.Finding{finding}
		}
		finding := model.NewFinding(event, "NTS-NATIVE-009", "Security audit policy changed", "Native telemetry reports an audit-policy change. In heightened mode this is investigated because it can reduce endpoint visibility.", "defense_evasion.audit_policy_change", model.SeverityHigh, 82)
		finding.MITRETactics = []string{"Defense Evasion"}
		finding.MITRETechniques = []string{"T1562.001"}
		finding.RecommendedSteps = []string{"Validate the change against an approved GPO or maintenance window", "Identify the account and source process", "Compare the active audit policy with the signed baseline"}
		return []model.Finding{finding}
	case "security.sysmon_config_change":
		finding := model.NewFinding(event, "NTS-NATIVE-010", "Sysmon configuration changed", "Sysmon configuration was changed. Validate that the new configuration preserves required telemetry coverage.", "defense_evasion.telemetry_config_change", model.SeverityHigh, 84)
		finding.MITRETactics = []string{"Defense Evasion"}
		finding.MITRETechniques = []string{"T1562.001"}
		finding.RecommendedSteps = []string{"Verify the configuration signer and change ticket", "Compare the active Sysmon configuration hash with the approved version", "Review adjacent process and log-clear events"}
		return []model.Finding{finding}
	case "identity.group_member_add":
		finding := model.NewFinding(event, "NTS-NATIVE-011", "Privileged group membership changed", "Native telemetry reports that an account was added to a local, domain, or universal group. Verify the target group and approving identity workflow.", "persistence.group_membership_change", model.SeverityHigh, 88)
		finding.MITRETactics = []string{"Persistence", "Privilege Escalation"}
		finding.MITRETechniques = []string{"T1098"}
		finding.RecommendedSteps = []string{"Identify the group, added account, and initiating account", "Check whether the group grants administrative access", "Validate the change against an approved identity workflow"}
		return []model.Finding{finding}
	case "identity.account_enable", "identity.account_password_reset":
		finding := model.NewFinding(event, "NTS-NATIVE-012", "Account access state changed", "Native telemetry reports an account enablement or password reset. In heightened mode this is reviewed for unauthorized account takeover or persistence.", "persistence.account_access_change", model.SeverityHigh, 84)
		finding.MITRETactics = []string{"Persistence", "Credential Access"}
		finding.MITRETechniques = []string{"T1098"}
		finding.RecommendedSteps = []string{"Identify the account and initiator", "Validate the change against the identity-management workflow", "Review interactive and remote logons immediately after the change"}
		return []model.Finding{finding}
	case "firewall.rule_change":
		finding := model.NewFinding(event, "NTS-NATIVE-013", "Windows Firewall rule changed", "A firewall rule was added, changed, or deleted. Review the affected ports, direction, and initiating account for potential exposure or defense evasion.", "defense_evasion.firewall_change", model.SeverityHigh, 82)
		finding.MITRETactics = []string{"Defense Evasion", "Command and Control"}
		finding.MITRETechniques = []string{"T1562.004"}
		finding.RecommendedSteps = []string{"Identify the exact rule and affected traffic", "Validate the initiating account and approved change ticket", "Correlate the change with new listeners and network connections"}
		return []model.Finding{finding}
	case "security.selinux_denial":
		if !strings.Contains(strings.ToLower(event.Message), "denied") {
			return nil
		}
		finding := model.NewFinding(event, "NTS-NATIVE-008", "SELinux denied a security-sensitive operation", "SELinux denied an operation. A single denial may be a configuration issue; repeated denials tied to exploit behavior increase confidence.", "linux.selinux_denial", model.SeverityMedium, 70)
		finding.MITRETactics = []string{"Execution", "Privilege Escalation"}
		finding.RecommendedSteps = []string{"Review the source context, target context, class, and permission", "Correlate the denial with process, file, and authentication events", "Do not disable SELinux as a troubleshooting shortcut"}
		return []model.Finding{finding}
	default:
		return nil
	}
}
