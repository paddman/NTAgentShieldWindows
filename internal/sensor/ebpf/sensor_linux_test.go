//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestNormalizeTCPEventIsDeterministicAndBounded(t *testing.T) {
	raw := wireEvent{TimestampNS: 55, CgroupID: 77, StartBootTimeNS: 99, PID: 101, TGID: 100, PPID: 1, UID: 1000, GID: 1000, Type: eventTCPConnect, Family: 2, Protocol: 6, SourcePort: 44444, DestinationPort: 443}
	copy(raw.Comm[:], "curl")
	copy(raw.Path[:], "/usr/bin/curl")
	copy(raw.SourceAddress[:4], []byte{127, 0, 0, 1})
	copy(raw.DestinationAddress[:4], []byte{1, 1, 1, 1})
	sensor := &Sensor{}
	first := sensor.normalize(raw)
	second := sensor.normalize(raw)
	if first.ID == "" || first.ID != second.ID || first.Kind != "network.connect" {
		t.Fatalf("unexpected normalized event identity: %#v", first)
	}
	if first.Process.PID != 100 || first.Process.PPID != 1 || first.Network.SourceIP != "127.0.0.1" || first.Network.DestinationIP != "1.1.1.1" || first.Network.DestinationPort != 443 {
		t.Fatalf("network event lost process or network attribution: %#v", first)
	}
	metadata := first.Attributes["ebpf"].(map[string]interface{})
	if metadata["cgroup_id"] != "77" || metadata["path"] != "/usr/bin/curl" {
		t.Fatalf("eBPF metadata was not preserved: %#v", metadata)
	}
}

func TestCapabilityCheckFailsClosedWithoutRequiredPair(t *testing.T) {
	data := [2]unix.CapUserData{}
	if hasBPFEffectiveCapabilities(data) {
		t.Fatal("empty capability set was accepted")
	}
	data[unix.CAP_BPF/32].Effective |= uint32(1) << (unix.CAP_BPF % 32)
	if hasBPFEffectiveCapabilities(data) {
		t.Fatal("CAP_BPF without CAP_PERFMON was accepted")
	}
	data[unix.CAP_PERFMON/32].Effective |= uint32(1) << (unix.CAP_PERFMON % 32)
	if !hasBPFEffectiveCapabilities(data) {
		t.Fatal("required CAP_BPF+CAP_PERFMON pair was rejected")
	}
}

func TestWireEventLayoutMatchesKernelABI(t *testing.T) {
	if size := binary.Size(wireEvent{}); size != 504 {
		t.Fatalf("unexpected eBPF wire event ABI size: %d", size)
	}
}

func TestNewRejectsUnsafeOrMissingProcessGraph(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("missing process graph was accepted")
	}
}

func TestEmbeddedCoreObjectContainsOnlyReviewedHooks(t *testing.T) {
	spec, err := cebpf.LoadCollectionSpecFromReader(bytes.NewReader(sensorObject))
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps["events"] == nil || spec.Maps["losses"] == nil {
		t.Fatalf("missing fixed sensor maps: %#v", spec.Maps)
	}
	if len(spec.Programs) != len(hooks) {
		t.Fatalf("unexpected embedded program count: got=%d want=%d", len(spec.Programs), len(hooks))
	}
	for _, hook := range hooks {
		if spec.Programs[hook.program] == nil {
			t.Fatalf("missing reviewed hook %q", hook.program)
		}
	}
}
