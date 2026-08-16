package agent

import (
	"strings"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestHighestFindingSeverity(t *testing.T) {
	findings := []model.Finding{
		{ID: "low", Severity: model.SeverityLow},
		{ID: "critical", Severity: model.SeverityCritical},
		{ID: "high", Severity: model.SeverityHigh},
	}
	if got := highestFindingSeverity(findings); got != model.SeverityCritical {
		t.Fatalf("unexpected highest severity: %s", got)
	}
	if severityRank(model.SeverityHigh) <= severityRank(model.SeverityMedium) {
		t.Fatal("severity ordering is invalid")
	}
}

func TestCompactAIEventOmitsOversizedAttributesAndText(t *testing.T) {
	event := model.Event{
		Message: strings.Repeat("m", maxAutomaticAITextBytes+100),
		Attributes: map[string]interface{}{
			"inventory": strings.Repeat("x", maxAutomaticAIAttributeBytes+100),
		},
	}
	compacted := compactAIEvent(event)
	if len(compacted.Message) >= len(event.Message) {
		t.Fatal("oversized message was not compacted")
	}
	if compacted.Attributes["automatic_ai_compaction"] != true {
		t.Fatalf("oversized attributes were not compacted: %#v", compacted.Attributes)
	}
	if _, exists := compacted.Attributes["inventory"]; exists {
		t.Fatal("oversized inventory remained in automatic AI evidence")
	}
}
