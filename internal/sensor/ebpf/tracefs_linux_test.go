//go:build linux

package ebpf

import "testing"

func TestTraceFSMountDataRequiresNumericNonRootGroup(t *testing.T) {
	value, err := traceFSMountData("119")
	if err != nil || value != "gid=119,mode=0750" {
		t.Fatalf("unexpected fixed tracefs mount data: value=%q err=%v", value, err)
	}
	for _, invalid := range []string{"", "0", "ntagentshield-sensor", "-1"} {
		if _, err := traceFSMountData(invalid); err == nil {
			t.Fatalf("invalid tracefs GID %q was accepted", invalid)
		}
	}
}
