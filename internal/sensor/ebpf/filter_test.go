package ebpf

import (
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestOperationalSelfEventFilter(t *testing.T) {
	tests := []struct {
		name  string
		event model.Event
		drop  bool
	}{
		{
			name:  "full agent image runtime write",
			event: ebpfFileEvent("file.write", "/usr/bin/ntagentshield-agent", "/var/lib/ntagentshield/evidence.journal.jsonl"),
			drop:  true,
		},
		{
			name:  "kernel comm truncated agent image",
			event: ebpfFileEvent("file.chmod", "ntagentshield-a", "/var/lib/ntagentshield/cursors/linux-audit.json"),
			drop:  true,
		},
		{
			name:  "external state tamper remains visible",
			event: ebpfFileEvent("file.unlink", "/usr/bin/rm", "/var/lib/ntagentshield/agent-identity.key"),
		},
		{
			name:  "agent config mutation remains visible",
			event: ebpfFileEvent("file.write", "ntagentshield-a", "/etc/ntagentshield/agent.json"),
		},
		{
			name:  "agent network telemetry remains visible",
			event: model.Event{Kind: "network.connect", Process: model.ProcessContext{Image: "ntagentshield-a"}, Provenance: model.Provenance{Collector: "linux-ebpf-core"}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isOperationalSelfEvent(test.event); got != test.drop {
				t.Fatalf("isOperationalSelfEvent()=%v, want %v", got, test.drop)
			}
		})
	}
}

func ebpfFileEvent(kind, image, path string) model.Event {
	return model.Event{
		Kind:       kind,
		Process:    model.ProcessContext{Image: image},
		Attributes: map[string]interface{}{"ebpf": map[string]interface{}{"path": path}},
		Provenance: model.Provenance{Collector: "linux-ebpf-core"},
	}
}
