package ebpf

import (
	"path/filepath"
	"strings"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

// isOperationalSelfEvent prevents the agent's evidence and cursor writes from
// feeding back through the eBPF stream. External access to the same paths is
// deliberately retained so tamper detection still sees it.
func isOperationalSelfEvent(event model.Event) bool {
	if event.Provenance.Collector != "linux-ebpf-core" || !strings.HasPrefix(event.Kind, "file.") {
		return false
	}
	image := strings.ToLower(filepath.Base(filepath.ToSlash(event.Process.Image)))
	if image != "ntagentshield-agent" && image != "ntagentshield-a" {
		return false
	}
	attributes, ok := event.Attributes["ebpf"].(map[string]interface{})
	if !ok {
		return false
	}
	path, _ := attributes["path"].(string)
	path = filepath.ToSlash(strings.ToLower(strings.TrimSpace(path)))
	return strings.HasPrefix(path, "/var/lib/ntagentshield/")
}
