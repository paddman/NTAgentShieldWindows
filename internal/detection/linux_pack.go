package detection

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

const (
	linuxDropTTL             = 10 * time.Minute
	linuxMaxRecentDrops      = 2048
	linuxMassChangeWindow    = 60 * time.Second
	linuxMassChangeThreshold = 32
	linuxMaxChangeProcesses  = 1024
	linuxMaxPathsPerProcess  = 128
)

// linuxDetectionPack is a fixed, offline-only rule pack. Evidence text is
// matched as data; no match can execute a command or authorize a response.
type linuxDetectionPack struct{}

type linuxRule struct {
	id            string
	title         string
	titleTH       string
	description   string
	descriptionTH string
	category      string
	response      string
	severity      model.Severity
	confidence    int
	tactics       []string
	techniques    []string
}

var linuxRules = []linuxRule{
	{id: "NTS-LNX-001", title: "Web service spawned a shell", titleTH: "บริการเว็บสร้างเชลล์", description: "A web worker spawned a command interpreter.", descriptionTH: "โปรเซสเว็บสร้างตัวแปลคำสั่ง ซึ่งอาจเป็น web shell หรือ exploitation.", category: "execution.web_shell", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 96, tactics: []string{"Initial Access", "Execution"}, techniques: []string{"T1190", "T1059"}},
	{id: "NTS-LNX-002", title: "Remote script piped to shell", titleTH: "สคริปต์จากเครือข่ายถูกส่งเข้าเชลล์", description: "curl or wget output was piped to a shell.", descriptionTH: "พบการส่งผลลัพธ์จาก curl หรือ wget เข้าเชลล์โดยตรง.", category: "execution.remote_script", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 95, tactics: []string{"Execution"}, techniques: []string{"T1059", "T1105"}},
	{id: "NTS-LNX-003", title: "Executable launched from a temporary path", titleTH: "รันไฟล์ปฏิบัติการจากพื้นที่ชั่วคราว", description: "An executable was launched from /tmp, /var/tmp, or /dev/shm.", descriptionTH: "พบการรันไฟล์ปฏิบัติการจาก /tmp, /var/tmp หรือ /dev/shm.", category: "execution.temp_binary", response: "file.quarantine", severity: model.SeverityHigh, confidence: 88, tactics: []string{"Execution", "Defense Evasion"}, techniques: []string{"T1059"}},
	{id: "NTS-LNX-004", title: "Systemd persistence changed", titleTH: "มีการเปลี่ยน persistence ของ systemd", description: "A systemd service or timer unit was modified.", descriptionTH: "พบการแก้ไข unit service หรือ timer ของ systemd.", category: "persistence.systemd", response: "file.quarantine", severity: model.SeverityHigh, confidence: 86, tactics: []string{"Persistence", "Privilege Escalation"}, techniques: []string{"T1543.002", "T1053.006"}},
	{id: "NTS-LNX-005", title: "Cron persistence changed", titleTH: "มีการเปลี่ยน persistence ของ cron", description: "A cron configuration or spool path was modified.", descriptionTH: "พบการแก้ไข cron configuration หรือ spool.", category: "persistence.cron", response: "file.quarantine", severity: model.SeverityHigh, confidence: 86, tactics: []string{"Persistence"}, techniques: []string{"T1053.003"}},
	{id: "NTS-LNX-006", title: "SSH authorized_keys modified", titleTH: "มีการแก้ไข SSH authorized_keys", description: "SSH authorized_keys was modified.", descriptionTH: "พบการแก้ไขไฟล์ SSH authorized_keys.", category: "persistence.ssh_keys", response: "file.quarantine", severity: model.SeverityHigh, confidence: 90, tactics: []string{"Persistence"}, techniques: []string{"T1098.004"}},
	{id: "NTS-LNX-007", title: "Sudoers modified", titleTH: "มีการแก้ไข sudoers", description: "A sudoers policy file was modified.", descriptionTH: "พบการแก้ไขนโยบาย sudoers.", category: "privilege_escalation.sudoers", response: "file.quarantine", severity: model.SeverityCritical, confidence: 94, tactics: []string{"Privilege Escalation", "Defense Evasion"}, techniques: []string{"T1548.003"}},
	{id: "NTS-LNX-008", title: "PAM configuration modified", titleTH: "มีการแก้ไข PAM", description: "A PAM configuration or module path was modified.", descriptionTH: "พบการแก้ไข PAM configuration หรือ module.", category: "persistence.pam", response: "file.quarantine", severity: model.SeverityCritical, confidence: 92, tactics: []string{"Persistence", "Credential Access"}, techniques: []string{"T1556"}},
	{id: "NTS-LNX-009", title: "Dynamic linker preload modified", titleTH: "มีการแก้ไข ld.so.preload", description: "The dynamic linker preload configuration was modified.", descriptionTH: "พบการแก้ไข /etc/ld.so.preload.", category: "persistence.ld_preload", response: "file.quarantine", severity: model.SeverityCritical, confidence: 96, tactics: []string{"Persistence", "Defense Evasion"}, techniques: []string{"T1574.006"}},
	{id: "NTS-LNX-010", title: "Security enforcement disabled", titleTH: "มีการปิดการบังคับใช้ความปลอดภัย", description: "SELinux or AppArmor enforcement appears to be disabled.", descriptionTH: "พบความพยายามปิด SELinux หรือ AppArmor.", category: "defense_evasion.security_control", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 92, tactics: []string{"Defense Evasion"}, techniques: []string{"T1562.001"}},
	{id: "NTS-LNX-011", title: "Security log deletion or truncation", titleTH: "มีการลบหรือตัดทอน security log", description: "A security logging path was deleted or truncated.", descriptionTH: "พบการลบหรือตัดทอนไฟล์ security log.", category: "defense_evasion.log_delete", response: "file.quarantine", severity: model.SeverityCritical, confidence: 93, tactics: []string{"Defense Evasion"}, techniques: []string{"T1070.002"}},
	{id: "NTS-LNX-012", title: "Suspicious kernel module load", titleTH: "มีการโหลด kernel module ที่น่าสงสัย", description: "A kernel module was loaded from an unusual path or by an unusual loader.", descriptionTH: "พบการโหลด kernel module จาก path หรือ loader ที่ผิดปกติ.", category: "defense_evasion.kernel_module", response: "process.terminate_tree", severity: model.SeverityHigh, confidence: 84, tactics: []string{"Persistence", "Defense Evasion"}, techniques: []string{"T1547.006"}},
	{id: "NTS-LNX-013", title: "Sensitive credential file access", titleTH: "มีการเข้าถึงไฟล์ credential สำคัญ", description: "A process accessed /etc/shadow or a private key.", descriptionTH: "พบการเข้าถึง /etc/shadow หรือ private key.", category: "credential_access.sensitive_file", response: "process.terminate_tree", severity: model.SeverityHigh, confidence: 84, tactics: []string{"Credential Access"}, techniques: []string{"T1003", "T1552.004"}},
	{id: "NTS-LNX-014", title: "Container escape indicator", titleTH: "พบสัญญาณ container escape", description: "Namespace or host-control access indicates possible container escape.", descriptionTH: "พบการเข้าถึง namespace หรือ host control ที่อาจเป็น container escape.", category: "privilege_escalation.container_escape", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 88, tactics: []string{"Privilege Escalation"}, techniques: []string{"T1611"}},
	{id: "NTS-LNX-015", title: "NTAgentShield tampering", titleTH: "พบการแก้ไข NTAgentShield", description: "The agent binary, configuration, policy, or service was modified or stopped.", descriptionTH: "พบการแก้ไขหรือหยุด binary, config, policy หรือ service ของ NTAgentShield.", category: "defense_evasion.agent_tamper", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 96, tactics: []string{"Defense Evasion"}, techniques: []string{"T1562.001"}},
	{id: "NTS-LNX-016", title: "Privilege account or group change", titleTH: "มีการเปลี่ยนบัญชีหรือกลุ่มสิทธิ์", description: "A Linux account or privileged group was changed.", descriptionTH: "พบการเปลี่ยนบัญชี Linux หรือกลุ่มที่มีสิทธิ์สูง.", category: "privilege_escalation.account_change", response: "process.terminate_tree", severity: model.SeverityHigh, confidence: 88, tactics: []string{"Persistence", "Privilege Escalation"}, techniques: []string{"T1098", "T1136"}},
	{id: "NTS-LNX-017", title: "Audit controls disabled", titleTH: "มีการปิด audit controls", description: "Linux audit enforcement appears disabled or weakened.", descriptionTH: "พบความพยายามปิดหรือทำให้ Linux audit อ่อนแอลง.", category: "defense_evasion.audit_disable", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 94, tactics: []string{"Defense Evasion"}, techniques: []string{"T1562.001"}},
	{id: "NTS-LNX-018", title: "Reverse shell behavior", titleTH: "พบพฤติกรรม reverse shell", description: "A shell or command interpreter initiated an outbound connection or used a known reverse-shell primitive.", descriptionTH: "พบ shell เชื่อมต่อออกหรือใช้รูปแบบคำสั่งที่สัมพันธ์กับ reverse shell.", category: "command_and_control.reverse_shell", response: "host.isolate", severity: model.SeverityCritical, confidence: 94, tactics: []string{"Execution", "Command and Control"}, techniques: []string{"T1059", "T1071"}},
}

var linuxRuleByID = func() map[string]linuxRule {
	rules := make(map[string]linuxRule, len(linuxRules)+2)
	for _, rule := range linuxRules {
		rules[rule.id] = rule
	}
	rules["NTS-LNX-019"] = linuxRule{id: "NTS-LNX-019", title: "File drop followed by execution", titleTH: "ไฟล์ถูกวางแล้วนำไปรันทันที", description: "A recently created or modified file was subsequently executed.", descriptionTH: "พบไฟล์ที่เพิ่งถูกสร้างหรือแก้ไขแล้วถูกนำไปรันภายในช่วงเวลาสั้น.", category: "execution.drop_and_execute", response: "file.quarantine", severity: model.SeverityCritical, confidence: 92, tactics: []string{"Execution", "Defense Evasion"}, techniques: []string{"T1105", "T1204"}}
	rules["NTS-LNX-020"] = linuxRule{id: "NTS-LNX-020", title: "Mass file modification behavior", titleTH: "พบการแก้ไขไฟล์จำนวนมาก", description: "One process modified many distinct files in a short window, which can precede ransomware impact.", descriptionTH: "โปรเซสเดียวแก้ไขไฟล์หลายไฟล์ในช่วงเวลาสั้น ซึ่งอาจเป็นสัญญาณก่อน ransomware.", category: "impact.mass_file_change", response: "process.terminate_tree", severity: model.SeverityCritical, confidence: 86, tactics: []string{"Impact"}, techniques: []string{"T1486"}}
	return rules
}()

func (linuxDetectionPack) ID() string { return "NTS-LNX-PACK" }

func (linuxDetectionPack) Evaluate(event model.Event) []model.Finding {
	text := eventText(event)
	findings := make([]model.Finding, 0, 2)
	for _, rule := range linuxRules {
		if linuxRuleMatches(rule.id, event, text) {
			findings = append(findings, newLinuxFinding(event, rule))
		}
	}
	return findings
}

func newLinuxFinding(event model.Event, rule linuxRule) model.Finding {
	finding := model.NewFinding(event, rule.id, rule.title, rule.description, rule.category, rule.severity, rule.confidence)
	if len(finding.ProcessTree) == 0 {
		// Linux findings retain the event's process slot even when a collector
		// could not resolve it, making the missing context explicit to analysts.
		finding.ProcessTree = []model.ProcessContext{event.Process}
	}
	finding.TitleTH = rule.titleTH
	finding.DescriptionTH = rule.descriptionTH
	finding.MITRETactics = append([]string(nil), rule.tactics...)
	finding.MITRETechniques = append([]string(nil), rule.techniques...)
	finding.RecommendedResponse = rule.response
	finding.RecommendedSteps = []string{
		"Preserve the evidence journal and process context",
		"Validate the activity against approved administration",
		"Use only the listed typed response after signed policy and approval checks",
	}
	return finding
}

func linuxRuleMatches(ruleID string, event model.Event, text string) bool {
	image := imageBase(event.Process.Image)
	parent := imageBase(event.Process.ParentImage)
	path := linuxEventPath(event)
	switch ruleID {
	case "NTS-LNX-001":
		return event.Kind == "process.exec" && isWebWorker(parent) && isShell(image)
	case "NTS-LNX-002":
		return event.Kind == "process.exec" && remoteDownloadPipedToShell(text)
	case "NTS-LNX-003":
		return event.Kind == "process.exec" && isTemporaryPath(event.Process.Image)
	case "NTS-LNX-004":
		return isFileMutation(event) && isSystemdUnitPath(path)
	case "NTS-LNX-005":
		return isFileMutation(event) && (strings.HasPrefix(path, "/etc/cron") || strings.HasPrefix(path, "/var/spool/cron"))
	case "NTS-LNX-006":
		return isFileMutation(event) && strings.HasSuffix(path, "/.ssh/authorized_keys")
	case "NTS-LNX-007":
		return isFileMutation(event) && (path == "/etc/sudoers" || strings.HasPrefix(path, "/etc/sudoers.d/"))
	case "NTS-LNX-008":
		return isFileMutation(event) && (strings.HasPrefix(path, "/etc/pam.d/") || strings.HasPrefix(path, "/usr/lib/security/") || strings.HasPrefix(path, "/usr/lib64/security/") || strings.HasPrefix(path, "/lib/security/"))
	case "NTS-LNX-009":
		return isFileMutation(event) && path == "/etc/ld.so.preload"
	case "NTS-LNX-010":
		return securityEnforcementDisabled(text)
	case "NTS-LNX-011":
		return isSecurityLogPath(path) && isLogDeletionOrTruncation(event, text)
	case "NTS-LNX-012":
		return event.Kind == "kernel.module_load" && suspiciousModuleLoad(event, text)
	case "NTS-LNX-013":
		return isFileAccess(event) && isSensitiveCredentialPath(path)
	case "NTS-LNX-014":
		return event.Kind == "process.namespace_change" || strings.Contains(text, "nsenter") || strings.Contains(text, "/proc/1/root") || strings.Contains(text, "/proc/1/ns/")
	case "NTS-LNX-015":
		return agentTamper(event, path, text)
	case "NTS-LNX-016":
		return privilegedIdentityChange(event, text)
	case "NTS-LNX-017":
		return (event.Kind == "security.audit_config" && (strings.Contains(text, "auditctl -e 0") || strings.Contains(text, "auditctl -d") || strings.Contains(text, "audit_enabled=0") || strings.Contains(text, "enabled=0"))) || (event.Kind == "service.stop" && strings.Contains(text, "auditd"))
	case "NTS-LNX-018":
		return reverseShellBehavior(event, text, image)
	default:
		return false
	}
}

type linuxDropObservation struct {
	at      time.Time
	eventID string
	process model.ProcessContext
}

type linuxChangeObservation struct {
	lastAt   time.Time
	paths    map[string]time.Time
	evidence map[string]string
	fired    bool
}

// linuxCorrelationRule keeps only bounded, short-lived local telemetry state.
// State is neither persisted as an instruction nor accepted from Central.
type linuxCorrelationRule struct {
	mu      sync.Mutex
	drops   map[string]linuxDropObservation
	changes map[string]*linuxChangeObservation
}

func newLinuxCorrelationRule() *linuxCorrelationRule {
	return &linuxCorrelationRule{drops: make(map[string]linuxDropObservation), changes: make(map[string]*linuxChangeObservation)}
}

func (*linuxCorrelationRule) ID() string { return "NTS-LNX-CORRELATION" }

func (r *linuxCorrelationRule) Evaluate(event model.Event) []model.Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := event.Timestamp.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	r.expire(now)
	findings := make([]model.Finding, 0, 2)
	path := linuxEventPath(event)
	if event.Kind == "process.exec" && path == "" {
		path = filepath.ToSlash(strings.ToLower(event.Process.Image))
	}
	if event.Kind == "process.exec" && path != "" {
		if dropped, exists := r.drops[path]; exists && !now.Before(dropped.at) && now.Sub(dropped.at) <= linuxDropTTL {
			finding := newLinuxFinding(event, linuxRuleByID["NTS-LNX-019"])
			finding.EvidenceEventIDs = distinctStrings(dropped.eventID, event.ID)
			finding.ProcessTree = distinctProcesses(dropped.process, event.Process)
			findings = append(findings, finding)
			delete(r.drops, path)
		}
	}
	if isFileMutation(event) && path != "" {
		if isFileDropEvent(event) {
			r.recordDrop(path, event, now)
		}
		if finding := r.recordChange(path, event, now); finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings
}

func (r *linuxCorrelationRule) expire(now time.Time) {
	for path, observation := range r.drops {
		if now.Sub(observation.at) > linuxDropTTL {
			delete(r.drops, path)
		}
	}
	for key, observation := range r.changes {
		for path, at := range observation.paths {
			if now.Sub(at) > linuxMassChangeWindow {
				delete(observation.paths, path)
				delete(observation.evidence, path)
			}
		}
		if len(observation.paths) == 0 || now.Sub(observation.lastAt) > linuxMassChangeWindow {
			delete(r.changes, key)
		} else if len(observation.paths) < linuxMassChangeThreshold {
			observation.fired = false
		}
	}
}

func (r *linuxCorrelationRule) recordDrop(path string, event model.Event, now time.Time) {
	current, exists := r.drops[path]
	if exists && now.Before(current.at) {
		return
	}
	if !exists && len(r.drops) >= linuxMaxRecentDrops {
		oldest := oldestDropKey(r.drops)
		delete(r.drops, oldest)
	}
	r.drops[path] = linuxDropObservation{at: now, eventID: event.ID, process: event.Process}
}

func (r *linuxCorrelationRule) recordChange(path string, event model.Event, now time.Time) *model.Finding {
	key := linuxProcessKey(event.Process)
	if key == "" {
		return nil
	}
	observation := r.changes[key]
	if observation == nil {
		if len(r.changes) >= linuxMaxChangeProcesses {
			delete(r.changes, oldestChangeKey(r.changes))
		}
		observation = &linuxChangeObservation{paths: make(map[string]time.Time), evidence: make(map[string]string)}
		r.changes[key] = observation
	}
	observation.lastAt = now
	if _, exists := observation.paths[path]; !exists && len(observation.paths) >= linuxMaxPathsPerProcess {
		oldest := oldestPathKey(observation.paths)
		delete(observation.paths, oldest)
		delete(observation.evidence, oldest)
	}
	observation.paths[path] = now
	observation.evidence[path] = event.ID
	if len(observation.paths) < linuxMassChangeThreshold || observation.fired {
		return nil
	}
	observation.fired = true
	finding := newLinuxFinding(event, linuxRuleByID["NTS-LNX-020"])
	finding.EvidenceEventIDs = sortedEvidence(observation.evidence)
	finding.Attributes["distinct_path_count"] = len(observation.paths)
	finding.Attributes["window_seconds"] = int(linuxMassChangeWindow.Seconds())
	return &finding
}

func oldestDropKey(entries map[string]linuxDropObservation) string {
	key := ""
	for candidate, entry := range entries {
		if key == "" || entry.at.Before(entries[key].at) || (entry.at.Equal(entries[key].at) && candidate < key) {
			key = candidate
		}
	}
	return key
}

func oldestChangeKey(entries map[string]*linuxChangeObservation) string {
	key := ""
	for candidate, entry := range entries {
		if key == "" || entry.lastAt.Before(entries[key].lastAt) || (entry.lastAt.Equal(entries[key].lastAt) && candidate < key) {
			key = candidate
		}
	}
	return key
}

func oldestPathKey(entries map[string]time.Time) string {
	key := ""
	for candidate, at := range entries {
		if key == "" || at.Before(entries[key]) || (at.Equal(entries[key]) && candidate < key) {
			key = candidate
		}
	}
	return key
}

func sortedEvidence(entries map[string]string) []string {
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	evidence := make([]string, 0, len(paths))
	for _, path := range paths {
		evidence = append(evidence, entries[path])
	}
	return evidence
}

func linuxEventPath(event model.Event) string {
	if event.File.Path != "" {
		return filepath.ToSlash(strings.ToLower(filepath.Clean(event.File.Path)))
	}
	if ebpf, ok := event.Attributes["ebpf"].(map[string]interface{}); ok {
		if path, ok := ebpf["path"].(string); ok && path != "" {
			return filepath.ToSlash(strings.ToLower(filepath.Clean(path)))
		}
	}
	if event.Kind == "process.exec" {
		return filepath.ToSlash(strings.ToLower(filepath.Clean(event.Process.Image)))
	}
	return ""
}

func isFileMutation(event model.Event) bool {
	switch event.Kind {
	case "file.write", "file.rename", "file.unlink", "file.chmod", "file.chown", "file.delete":
		return true
	}
	switch strings.ToLower(event.File.Operation) {
	case "create", "modify", "write", "rename", "delete", "unlink", "truncate", "chmod", "chown":
		return true
	default:
		return false
	}
}

func isFileDropEvent(event model.Event) bool {
	switch event.Kind {
	case "file.write", "file.rename":
		return true
	}
	switch strings.ToLower(event.File.Operation) {
	case "create", "modify", "write", "rename":
		return true
	default:
		return false
	}
}

func isFileAccess(event model.Event) bool {
	return event.Kind == "file.open" || event.Kind == "file.access" || isFileMutation(event)
}

func isWebWorker(image string) bool {
	switch image {
	case "nginx", "apache2", "httpd", "php-fpm", "php-fpm8.1", "php-fpm8.2", "php-fpm8.3":
		return true
	default:
		return false
	}
}

func isShell(image string) bool {
	switch image {
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return true
	default:
		return false
	}
}

var remotePipeShellPattern = regexp.MustCompile(`(?:^|[\s/])(curl|wget)(?:\s|$)[^\n|]*\|\s*(?:sudo\s+)?(?:/[a-z0-9._-]+/)*(?:sh|bash|dash|zsh|ksh|ash)(?:\s|$)`)

func remoteDownloadPipedToShell(text string) bool { return remotePipeShellPattern.MatchString(text) }

func isTemporaryPath(path string) bool {
	path = filepath.ToSlash(strings.ToLower(path))
	return strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") || strings.HasPrefix(path, "/dev/shm/")
}

func isSystemdUnitPath(path string) bool {
	if !strings.HasSuffix(path, ".service") && !strings.HasSuffix(path, ".timer") {
		return false
	}
	return strings.HasPrefix(path, "/etc/systemd/system/") || strings.HasPrefix(path, "/run/systemd/system/") || strings.HasPrefix(path, "/usr/lib/systemd/system/") || strings.HasPrefix(path, "/lib/systemd/system/") || strings.Contains(path, "/.config/systemd/user/")
}

func securityEnforcementDisabled(text string) bool {
	patterns := []string{"setenforce 0", "setenforce=0", "selinux=0", "enforcing=0", "apparmor=0", "aa-disable ", "apparmor_parser -r /etc/apparmor.d/disable"}
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func isSecurityLogPath(path string) bool {
	switch path {
	case "/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log", "/var/log/syslog", "/var/log/messages", "/var/log/kern.log":
		return true
	default:
		return strings.HasPrefix(path, "/var/log/audit/")
	}
}

func isLogDeletionOrTruncation(event model.Event, text string) bool {
	return event.Kind == "file.unlink" || event.Kind == "file.delete" || event.File.Operation == "truncate" || strings.Contains(text, "truncate") || strings.Contains(text, "o_trunc")
}

func suspiciousModuleLoad(event model.Event, text string) bool {
	path := linuxEventPath(event)
	loader := imageBase(event.Process.Image)
	unusualPath := path != "" && !strings.HasPrefix(path, "/lib/modules/") && !strings.HasPrefix(path, "/usr/lib/modules/")
	unusualLoader := loader != "" && loader != "modprobe" && loader != "kmod" && loader != "systemd-modules-load"
	return unusualPath || unusualLoader || isTemporaryPath(path) || strings.Contains(text, "unsigned") || strings.Contains(text, "taint")
}

func isSensitiveCredentialPath(path string) bool {
	if path == "/etc/shadow" || path == "/etc/gshadow" {
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	if base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" || base == "id_ed25519" {
		return true
	}
	return (strings.Contains(path, "/.ssh/") || strings.Contains(path, "/private/")) && (strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key"))
}

func agentTamper(event model.Event, path, text string) bool {
	protectedPath := strings.HasPrefix(path, "/etc/ntagentshield/") || strings.HasPrefix(path, "/var/lib/ntagentshield/") || strings.Contains(path, "/ntagentshield-agent") || strings.Contains(path, "/ntagentshield-sensor") || strings.Contains(path, "/ntagentshield-response")
	if protectedPath && isFileMutation(event) {
		return true
	}
	return (event.Kind == "service.stop" || event.Kind == "security.audit_config") && strings.Contains(text, "ntagentshield")
}

func privilegedIdentityChange(event model.Event, text string) bool {
	switch event.Kind {
	case "identity.account_create", "identity.group_modify", "identity.group_member_add", "identity.setuid", "identity.setgid":
		return true
	}
	return (strings.Contains(text, "usermod") || strings.Contains(text, "groupadd") || strings.Contains(text, "gpasswd")) && (strings.Contains(text, "sudo") || strings.Contains(text, "wheel") || strings.Contains(text, " uid=0") || strings.Contains(text, "gid=0"))
}

func reverseShellBehavior(event model.Event, text, image string) bool {
	knownPrimitive := strings.Contains(text, "/dev/tcp/") || strings.Contains(text, "/dev/udp/") || (strings.Contains(text, "nc ") && strings.Contains(text, " -e")) || (strings.Contains(text, "ncat ") && strings.Contains(text, " --exec")) || (strings.Contains(text, "socat ") && strings.Contains(text, "exec:")) || (strings.Contains(text, "dup2(") && strings.Contains(text, "socket"))
	if knownPrimitive {
		return true
	}
	return event.Kind == "network.connect" && isShell(image) && event.Network.DestinationIP != "" && event.Network.DestinationPort > 0
}

func linuxProcessKey(process model.ProcessContext) string {
	if process.ProcessGUID != "" {
		return process.ProcessGUID
	}
	if process.PID > 0 && process.StartTimeTicks > 0 {
		return strings.Join([]string{process.Image, strconv.Itoa(process.PID), strconv.FormatUint(process.StartTimeTicks, 10)}, "\x00")
	}
	return ""
}

func distinctStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func distinctProcesses(values ...model.ProcessContext) []model.ProcessContext {
	seen := make(map[string]struct{}, len(values))
	result := make([]model.ProcessContext, 0, len(values))
	for _, value := range values {
		key := linuxProcessKey(value)
		if key == "" {
			key = value.Image + "\x00" + value.CommandLine
		}
		if key == "\x00" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}
