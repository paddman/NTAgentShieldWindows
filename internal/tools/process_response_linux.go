//go:build linux

package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type linuxProcessResponseBackend struct{ procRoot string }

func newProcessResponseBackend() processResponseBackend {
	return linuxProcessResponseBackend{procRoot: "/proc"}
}

func (b linuxProcessResponseBackend) Target(pid int) (processResponseTarget, error) {
	content, err := os.ReadFile(filepath.Join(b.procRoot, strconv.Itoa(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return processResponseTarget{}, os.ErrNotExist
	}
	if err != nil {
		return processResponseTarget{}, fmt.Errorf("read process %d identity: %w", pid, err)
	}
	closeIndex := strings.LastIndexByte(string(content), ')')
	if closeIndex < 0 || closeIndex+2 >= len(content) {
		return processResponseTarget{}, errors.New("invalid Linux process stat format")
	}
	fields := strings.Fields(string(content[closeIndex+2:]))
	if len(fields) < 20 {
		return processResponseTarget{}, errors.New("incomplete Linux process stat identity")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return processResponseTarget{}, errors.New("invalid Linux process parent PID")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || startTicks == 0 {
		return processResponseTarget{}, errors.New("invalid Linux process start ticks")
	}
	image, _ := os.Readlink(filepath.Join(b.procRoot, strconv.Itoa(pid), "exe"))
	return processResponseTarget{PID: pid, PPID: ppid, StartTicks: startTicks, Image: image, State: fields[0]}, nil
}

func (b linuxProcessResponseBackend) Snapshot(maximum int) ([]processResponseTarget, error) {
	entries, err := os.ReadDir(b.procRoot)
	if err != nil {
		return nil, err
	}
	result := make([]processResponseTarget, 0, min(maximum, len(entries)))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if len(result) >= maximum {
			return nil, errors.New("process response scan reached its fixed safety bound")
		}
		target, err := b.Target(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			continue
		}
		if target.State != "Z" {
			result = append(result, target)
		}
	}
	return result, nil
}

func (linuxProcessResponseBackend) Terminate(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func (b linuxProcessResponseBackend) WaitExited(ctx context.Context, target processResponseTarget) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		current, err := b.Target(target.PID)
		if errors.Is(err, os.ErrNotExist) || err == nil && (current.StartTicks != target.StartTicks || current.State == "Z") {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("process identity still exists after termination")
		case <-ticker.C:
		}
	}
}
