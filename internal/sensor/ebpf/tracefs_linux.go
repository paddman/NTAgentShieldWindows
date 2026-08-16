//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

const traceFSPath = "/sys/kernel/tracing"
const traceFSGroup = "ntagentshield-sensor"

// PrepareTraceFS performs one fixed remount so the telemetry-only Sensor can
// read tracepoint IDs without receiving a broad filesystem capability.
func PrepareTraceFS() error {
	if os.Geteuid() != 0 {
		return errors.New("tracefs preparation requires the fixed root one-shot service")
	}
	group, err := user.LookupGroup(traceFSGroup)
	if err != nil {
		return fmt.Errorf("resolve fixed tracefs sensor group: %w", err)
	}
	data, err := traceFSMountData(group.Gid)
	if err != nil {
		return err
	}
	flags := uintptr(unix.MS_REMOUNT | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if err := unix.Mount("tracefs", traceFSPath, "tracefs", flags, data); err != nil {
		return fmt.Errorf("remount fixed tracefs sensor view: %w", err)
	}
	return nil
}

func traceFSMountData(groupID string) (string, error) {
	value, err := strconv.ParseUint(groupID, 10, 32)
	if err != nil || value == 0 {
		return "", errors.New("fixed tracefs sensor group has an invalid numeric GID")
	}
	return fmt.Sprintf("gid=%d,mode=0750", value), nil
}
