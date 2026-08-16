package tools

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestProcessTerminateRejectsSystemAndAgentPID(t *testing.T) {
	tool := ProcessTerminate{}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": 1}); err == nil || !strings.Contains(err.Error(), "non-system") {
		t.Fatalf("expected system PID rejection, got %v", err)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": os.Getpid()}); err == nil || !strings.Contains(err.Error(), "NTAgentShield") {
		t.Fatalf("expected self-termination rejection, got %v", err)
	}
}

type fakeProcessResponseBackend struct {
	targets map[int]processResponseTarget
	killed  []int
	missing map[int]bool
}

func (f *fakeProcessResponseBackend) Target(pid int) (processResponseTarget, error) {
	if f.missing[pid] {
		return processResponseTarget{}, os.ErrNotExist
	}
	target, exists := f.targets[pid]
	if !exists {
		return processResponseTarget{}, os.ErrNotExist
	}
	return target, nil
}
func (f *fakeProcessResponseBackend) Snapshot(maximum int) ([]processResponseTarget, error) {
	if len(f.targets) > maximum {
		return nil, errors.New("bounded")
	}
	result := make([]processResponseTarget, 0, len(f.targets))
	for _, target := range f.targets {
		result = append(result, target)
	}
	return result, nil
}
func (f *fakeProcessResponseBackend) Terminate(pid int) error {
	f.killed = append(f.killed, pid)
	return nil
}
func (*fakeProcessResponseBackend) WaitExited(context.Context, processResponseTarget) error {
	return nil
}

func TestProcessTerminateRequiresAndVerifiesStartTicks(t *testing.T) {
	backend := &fakeProcessResponseBackend{targets: map[int]processResponseTarget{100: {PID: 100, PPID: 1, StartTicks: 55, Image: "/usr/bin/test"}}, missing: map[int]bool{}}
	tool := ProcessTerminate{backend: backend}
	if _, err := tool.Execute(t.Context(), map[string]interface{}{"pid": 100}); err == nil || !strings.Contains(err.Error(), "expected_start_time_ticks") {
		t.Fatalf("missing PID identity was accepted: %v", err)
	}
	if _, err := tool.Execute(t.Context(), map[string]interface{}{"pid": 100, "expected_start_time_ticks": 54}); err == nil || !strings.Contains(err.Error(), "reused") {
		t.Fatalf("PID reuse mismatch was accepted: %v", err)
	}
	result, err := tool.Execute(t.Context(), map[string]interface{}{"pid": 100, "expected_start_time_ticks": 55})
	if err != nil || !reflect.DeepEqual(backend.killed, []int{100}) || result.(map[string]interface{})["verified"] != true {
		t.Fatalf("verified termination failed: result=%#v killed=%v err=%v", result, backend.killed, err)
	}
}

func TestProcessTerminateTreeKillsChildrenBeforeParent(t *testing.T) {
	backend := &fakeProcessResponseBackend{targets: map[int]processResponseTarget{
		100: {PID: 100, PPID: 1, StartTicks: 10, Image: "/usr/bin/root"},
		101: {PID: 101, PPID: 100, StartTicks: 11, Image: "/usr/bin/child"},
		102: {PID: 102, PPID: 101, StartTicks: 12, Image: "/usr/bin/grandchild"},
		200: {PID: 200, PPID: 1, StartTicks: 20, Image: "/usr/bin/unrelated"},
	}, missing: map[int]bool{}}
	result, err := (ProcessTerminateTree{backend: backend}).Execute(t.Context(), map[string]interface{}{"pid": 100, "expected_start_time_ticks": 10})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(backend.killed, []int{102, 101, 100}) {
		t.Fatalf("unsafe tree termination order: %v", backend.killed)
	}
	if result.(map[string]interface{})["terminated_processes"] != 3 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestProcessTerminateRejectsFractionalAndUnknownArguments(t *testing.T) {
	tool := ProcessTerminate{}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": 123.5}); err == nil || !strings.Contains(err.Error(), "exact") {
		t.Fatalf("expected fractional PID rejection, got %v", err)
	}
	if _, err := tool.Execute(context.Background(), map[string]interface{}{"pid": 123, "name": "anything"}); err == nil || !strings.Contains(err.Error(), "unsupported argument") {
		t.Fatalf("expected unknown argument rejection, got %v", err)
	}
}
