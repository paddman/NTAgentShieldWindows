// Package processgraph maintains a bounded, local-only view of Linux
// processes. It consumes /proc as untrusted telemetry and never grants any
// response authority.
package processgraph

import "time"

const stateVersion = 1

type Options struct {
	ProcRoot               string
	StatePath              string
	MaxProcesses           int
	MaxExitedProcesses     int
	MaxCommandLineBytes    int
	MaxExecutableHashBytes int64
}

type Process struct {
	ProcessGUID       string            `json:"process_guid"`
	ParentProcessGUID string            `json:"parent_process_guid,omitempty"`
	BootIDHash        string            `json:"boot_id_hash"`
	PID               int               `json:"pid"`
	PPID              int               `json:"ppid,omitempty"`
	StartTimeTicks    uint64            `json:"start_time_ticks"`
	Executable        string            `json:"executable,omitempty"`
	CommandLine       string            `json:"command_line,omitempty"`
	CommandTruncated  bool              `json:"command_truncated,omitempty"`
	UID               uint32            `json:"uid,omitempty"`
	EUID              uint32            `json:"euid,omitempty"`
	GID               uint32            `json:"gid,omitempty"`
	EGID              uint32            `json:"egid,omitempty"`
	Username          string            `json:"username,omitempty"`
	LoginUID          string            `json:"login_uid,omitempty"`
	Session           string            `json:"session,omitempty"`
	Namespaces        map[string]string `json:"namespaces,omitempty"`
	Cgroup            string            `json:"cgroup,omitempty"`
	ContainerID       string            `json:"container_id,omitempty"`
	Capabilities      map[string]string `json:"capabilities,omitempty"`
	ExecutableSHA256  string            `json:"executable_sha256,omitempty"`
	ExecutableInode   uint64            `json:"executable_inode,omitempty"`
	ExecutableDevice  uint64            `json:"executable_device,omitempty"`
	StartedAt         time.Time         `json:"started_at"`
	ObservedAt        time.Time         `json:"observed_at"`
	StoppedAt         *time.Time        `json:"stopped_at,omitempty"`
	ExitReason        string            `json:"exit_reason,omitempty"`
}

type Stats struct {
	ActiveProcesses int       `json:"active_processes"`
	ExitedProcesses int       `json:"exited_processes"`
	Reconciliations uint64    `json:"reconciliations"`
	ObservedStarts  uint64    `json:"observed_starts"`
	ObservedExits   uint64    `json:"observed_exits"`
	ScanErrors      uint64    `json:"scan_errors"`
	LastReconciled  time.Time `json:"last_reconciled,omitempty"`
}

type persistedState struct {
	Version    int       `json:"version"`
	BootIDHash string    `json:"boot_id_hash"`
	Active     []Process `json:"active"`
	Exited     []Process `json:"exited,omitempty"`
	Stats      Stats     `json:"stats"`
}
