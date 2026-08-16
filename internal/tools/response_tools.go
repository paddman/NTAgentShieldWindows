package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

const maxResponseProcessScan = 4096

type processResponseTarget struct {
	PID        int
	PPID       int
	StartTicks uint64
	Image      string
	State      string
}

type processResponseBackend interface {
	Target(int) (processResponseTarget, error)
	Snapshot(int) ([]processResponseTarget, error)
	Terminate(int) error
	WaitExited(context.Context, processResponseTarget) error
}

type ProcessTerminate struct{ backend processResponseBackend }
type ProcessTerminateTree struct{ backend processResponseBackend }

func (ProcessTerminate) Spec() Spec {
	return Spec{Name: "process.terminate", Description: "Terminate one exact PID/start-time identity after signed approval", Risk: model.RiskContain}
}

func (ProcessTerminateTree) Spec() Spec {
	return Spec{Name: "process.terminate_tree", Description: "Terminate one exact PID/start-time tree with bounded descendant discovery", Risk: model.RiskContain}
}

func (t ProcessTerminate) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := rejectUnknownArgs(args, "pid", "expected_start_time_ticks"); err != nil {
		return nil, err
	}
	target, backend, already, err := resolveProcessResponse(t.backend, args)
	if err != nil {
		return nil, err
	}
	if already {
		return map[string]interface{}{"pid": target.PID, "terminated": true, "already_terminated": true, "verified": true}, nil
	}
	if err := backend.Terminate(target.PID); err != nil {
		return nil, fmt.Errorf("terminate process %d: %w", target.PID, err)
	}
	if err := backend.WaitExited(ctx, target); err != nil {
		return nil, fmt.Errorf("verify process %d termination: %w", target.PID, err)
	}
	return map[string]interface{}{"pid": target.PID, "start_time_ticks": target.StartTicks, "terminated": true, "verified": true}, nil
}

func (t ProcessTerminateTree) Execute(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	if err := rejectUnknownArgs(args, "pid", "expected_start_time_ticks"); err != nil {
		return nil, err
	}
	root, backend, already, err := resolveProcessResponse(t.backend, args)
	if err != nil {
		return nil, err
	}
	if already {
		return map[string]interface{}{"pid": root.PID, "terminated": true, "already_terminated": true, "terminated_processes": 0, "verified": true}, nil
	}
	processes, err := backend.Snapshot(maxResponseProcessScan)
	if err != nil {
		return nil, fmt.Errorf("snapshot process tree: %w", err)
	}
	targets := descendants(root, processes)
	sort.Slice(targets, func(i, j int) bool {
		left, right := processDepth(targets[i], targets), processDepth(targets[j], targets)
		if left != right {
			return left > right
		}
		return targets[i].PID > targets[j].PID
	})
	terminated, disappeared, reused := 0, 0, 0
	for _, target := range targets {
		current, targetErr := backend.Target(target.PID)
		if errors.Is(targetErr, os.ErrNotExist) {
			disappeared++
			continue
		}
		if targetErr != nil {
			return nil, targetErr
		}
		if current.StartTicks != target.StartTicks {
			reused++
			continue
		}
		if protectedResponseProcess(current) {
			return nil, fmt.Errorf("refusing to terminate protected NTAgentShield process pid=%d", current.PID)
		}
		if err := backend.Terminate(current.PID); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return nil, fmt.Errorf("terminate tree process %d: %w", current.PID, err)
		}
		if err := backend.WaitExited(ctx, current); err != nil {
			return nil, fmt.Errorf("verify tree process %d termination: %w", current.PID, err)
		}
		terminated++
	}
	return map[string]interface{}{"pid": root.PID, "start_time_ticks": root.StartTicks, "terminated": true, "verified": true, "terminated_processes": terminated, "disappeared_processes": disappeared, "pid_reuse_skipped": reused}, nil
}

func resolveProcessResponse(configured processResponseBackend, args map[string]interface{}) (processResponseTarget, processResponseBackend, bool, error) {
	pid, err := exactPIDArg(args)
	if err != nil {
		return processResponseTarget{}, nil, false, err
	}
	if pid <= 4 {
		return processResponseTarget{}, nil, false, errors.New("pid must identify a non-system process greater than 4")
	}
	if pid == os.Getpid() {
		return processResponseTarget{}, nil, false, errors.New("refusing to terminate the NTAgentShield response process")
	}
	expected, err := exactUint64Arg(args, "expected_start_time_ticks")
	if err != nil {
		return processResponseTarget{}, nil, false, err
	}
	backend := configured
	if backend == nil {
		backend = newProcessResponseBackend()
	}
	target, err := backend.Target(pid)
	if errors.Is(err, os.ErrNotExist) {
		return processResponseTarget{PID: pid, StartTicks: expected}, backend, true, nil
	}
	if err != nil {
		return processResponseTarget{}, nil, false, err
	}
	if target.StartTicks != expected {
		return processResponseTarget{}, nil, false, errors.New("process start ticks mismatch; PID may have been reused")
	}
	if protectedResponseProcess(target) {
		return processResponseTarget{}, nil, false, fmt.Errorf("refusing to terminate protected NTAgentShield process pid=%d", pid)
	}
	return target, backend, false, nil
}

func protectedResponseProcess(target processResponseTarget) bool {
	base := strings.ToLower(filepath.Base(target.Image))
	if strings.HasPrefix(base, "ntagentshield-") || base == "ntagentshield" {
		return true
	}
	switch base {
	case "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe":
		return true
	default:
		return false
	}
}

// TerminateVerifiedProcess is the narrow local-protection entry point. It
// resolves an exact process identity, verifies the expected executable path,
// applies the protected-process denylist, terminates, and confirms exit. It
// does not accept a command string or arbitrary executable.
func TerminateVerifiedProcess(ctx context.Context, pid int, expectedImage string) (map[string]interface{}, error) {
	if pid <= 4 || strings.TrimSpace(expectedImage) == "" {
		return nil, errors.New("a non-system pid and expected image are required")
	}
	backend := newProcessResponseBackend()
	target, err := backend.Target(pid)
	if err != nil {
		return nil, err
	}
	actualPath, actualErr := filepath.Abs(target.Image)
	expectedPath, expectedErr := filepath.Abs(expectedImage)
	if actualErr != nil || expectedErr != nil || !strings.EqualFold(filepath.Clean(actualPath), filepath.Clean(expectedPath)) {
		return nil, errors.New("process executable identity does not match the protection verdict")
	}
	if protectedResponseProcess(target) {
		return nil, fmt.Errorf("refusing to terminate protected process pid=%d", pid)
	}
	if err := backend.Terminate(pid); err != nil {
		return nil, err
	}
	if err := backend.WaitExited(ctx, target); err != nil {
		return nil, err
	}
	return map[string]interface{}{"pid": pid, "start_time_ticks": target.StartTicks, "terminated": true, "verified": true}, nil
}

func descendants(root processResponseTarget, processes []processResponseTarget) []processResponseTarget {
	selected := map[int]processResponseTarget{root.PID: root}
	changed := true
	for changed {
		changed = false
		for _, process := range processes {
			if _, exists := selected[process.PID]; exists {
				continue
			}
			if _, parentSelected := selected[process.PPID]; parentSelected {
				selected[process.PID] = process
				changed = true
			}
		}
	}
	result := make([]processResponseTarget, 0, len(selected))
	for _, process := range selected {
		result = append(result, process)
	}
	return result
}

func processDepth(target processResponseTarget, targets []processResponseTarget) int {
	parents := make(map[int]int, len(targets))
	for _, process := range targets {
		parents[process.PID] = process.PPID
	}
	depth, pid := 0, target.PID
	for depth <= len(targets) {
		parent, exists := parents[pid]
		if !exists {
			break
		}
		depth++
		pid = parent
	}
	return depth
}
