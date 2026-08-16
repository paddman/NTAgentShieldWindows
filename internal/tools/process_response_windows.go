//go:build windows

package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcessResponseBackend struct {
	mu       sync.Mutex
	expected map[int]uint64
}

func newProcessResponseBackend() processResponseBackend {
	return &windowsProcessResponseBackend{expected: map[int]uint64{}}
}

func (b *windowsProcessResponseBackend) Target(pid int) (processResponseTarget, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_FOUND) {
			return processResponseTarget{}, os.ErrNotExist
		}
		return processResponseTarget{}, fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)
	creation, err := windowsProcessCreation(handle)
	if err != nil {
		return processResponseTarget{}, err
	}
	image := windowsProcessImage(handle)
	ppid := windowsParentPID(uint32(pid))
	b.mu.Lock()
	b.expected[pid] = creation
	b.mu.Unlock()
	return processResponseTarget{PID: pid, PPID: ppid, StartTicks: creation, Image: image, State: "running"}, nil
}

func (b *windowsProcessResponseBackend) Snapshot(maximum int) ([]processResponseTarget, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}
	result := make([]processResponseTarget, 0, min(maximum, 256))
	for {
		if len(result) >= maximum {
			return nil, errors.New("Windows process response scan reached its fixed safety bound")
		}
		if entry.ProcessID > 4 {
			if target, targetErr := b.Target(int(entry.ProcessID)); targetErr == nil {
				target.PPID = int(entry.ParentProcessID)
				result = append(result, target)
			}
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			if errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, err
		}
	}
	return result, nil
}

func (b *windowsProcessResponseBackend) Terminate(pid int) error {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	actual, err := windowsProcessCreation(handle)
	if err != nil {
		return err
	}
	b.mu.Lock()
	expected, exists := b.expected[pid]
	b.mu.Unlock()
	if !exists || actual != expected {
		return errors.New("process creation time changed before termination; PID reuse refused")
	}
	return windows.TerminateProcess(handle, 1)
}

func (b *windowsProcessResponseBackend) WaitExited(ctx context.Context, target processResponseTarget) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		current, err := b.Target(target.PID)
		if errors.Is(err, os.ErrNotExist) || err == nil && current.StartTicks != target.StartTicks {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("process identity still exists after Windows termination")
		case <-ticker.C:
		}
	}
}

func windowsProcessCreation(handle windows.Handle) (uint64, error) {
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(uint32(creation.HighDateTime))<<32 | uint64(creation.LowDateTime), nil
}

func windowsProcessImage(handle windows.Handle) string {
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buffer[:size])
}

func windowsParentPID(pid uint32) int {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	for {
		if entry.ProcessID == pid {
			return int(entry.ParentProcessID)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			return 0
		}
	}
}
