package processgraph

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/redact"
)

const (
	maxProcStatBytes   = 64 * 1024
	maxProcStatusBytes = 128 * 1024
	maxProcCgroupBytes = 64 * 1024
	maxWarnings        = 32
	auxvClockTicks     = 17
)

var containerIDPattern = regexp.MustCompile(`(?i)(?:docker-|cri-containerd-|crio-)?([a-f0-9]{12,64})(?:\.scope)?`)

type procScan struct {
	processes      []Process
	unresolvedPIDs map[int]bool
	warnings       []string
	complete       bool
}

type procStat struct {
	pid        int
	ppid       int
	startTicks uint64
}

func scanProcesses(ctx context.Context, options Options, bootIDHash string, bootTime time.Time, clockHz uint64) (procScan, error) {
	entries, err := os.ReadDir(options.ProcRoot)
	if err != nil {
		return procScan{}, fmt.Errorf("read proc root: %w", err)
	}
	result := procScan{unresolvedPIDs: make(map[int]bool), complete: true}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if len(result.processes) >= options.MaxProcesses {
			result.complete = false
			appendWarning(&result.warnings, "process scan reached configured maximum")
			break
		}
		process, err := readProcess(options, pid, bootIDHash, bootTime, clockHz)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			result.unresolvedPIDs[pid] = true
			appendWarning(&result.warnings, fmt.Sprintf("pid %d: %s", pid, boundedError(err)))
			continue
		}
		result.processes = append(result.processes, process)
	}
	sort.Slice(result.processes, func(i, j int) bool { return result.processes[i].PID < result.processes[j].PID })
	return result, nil
}

func readProcess(options Options, pid int, bootIDHash string, bootTime time.Time, clockHz uint64) (Process, error) {
	base := filepath.Join(options.ProcRoot, strconv.Itoa(pid))
	statContent, err := readFileLimited(filepath.Join(base, "stat"), maxProcStatBytes)
	if err != nil {
		return Process{}, err
	}
	stat, err := parseProcStat(string(statContent))
	if err != nil {
		return Process{}, err
	}
	statusContent, err := readFileLimited(filepath.Join(base, "status"), maxProcStatusBytes)
	if err != nil {
		return Process{}, err
	}
	status := parseProcStatus(string(statusContent))
	uid, euid := parseIDPair(status["Uid"])
	gid, egid := parseIDPair(status["Gid"])
	commandLine, commandTruncated, err := readCommandLine(filepath.Join(base, "cmdline"), options.MaxCommandLineBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
		return Process{}, err
	}
	// This value is persisted in the graph checkpoint before it reaches the
	// runtime journal, so redact it at collection time as well.
	commandLine = redact.String(commandLine)
	executable, _ := os.Readlink(filepath.Join(base, "exe"))
	loginUID, _ := readTrimmedLimited(filepath.Join(base, "loginuid"), 64)
	session, _ := readTrimmedLimited(filepath.Join(base, "sessionid"), 64)
	cgroup, _ := readTrimmedLimited(filepath.Join(base, "cgroup"), maxProcCgroupBytes)
	namespaces := readNamespaces(base)
	sha256Value, inode, device := executableIdentity(base, options.MaxExecutableHashBytes)
	process := Process{
		BootIDHash:       bootIDHash,
		PID:              stat.pid,
		PPID:             stat.ppid,
		StartTimeTicks:   stat.startTicks,
		Executable:       executable,
		CommandLine:      commandLine,
		CommandTruncated: commandTruncated,
		UID:              uid,
		EUID:             euid,
		GID:              gid,
		EGID:             egid,
		Username:         lookupUsername(uid),
		LoginUID:         loginUID,
		Session:          session,
		Namespaces:       namespaces,
		Cgroup:           cgroup,
		ContainerID:      parseContainerID(cgroup),
		Capabilities:     capabilityFields(status),
		ExecutableSHA256: sha256Value,
		ExecutableInode:  inode,
		ExecutableDevice: device,
	}
	process.ProcessGUID = ProcessGUID(bootIDHash, process.PID, process.StartTimeTicks)
	if !bootTime.IsZero() && clockHz > 0 {
		seconds := process.StartTimeTicks / clockHz
		nanoseconds := (process.StartTimeTicks % clockHz) * uint64(time.Second) / clockHz
		process.StartedAt = bootTime.Add(time.Duration(seconds)*time.Second + time.Duration(nanoseconds)).UTC()
	}
	return process, nil
}

func parseProcStat(content string) (procStat, error) {
	content = strings.TrimSpace(content)
	open := strings.IndexByte(content, '(')
	close := strings.LastIndexByte(content, ')')
	if open <= 0 || close <= open || close+2 >= len(content) {
		return procStat{}, errors.New("invalid proc stat format")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(content[:open]))
	if err != nil || pid <= 0 {
		return procStat{}, errors.New("invalid proc stat pid")
	}
	fields := strings.Fields(content[close+1:])
	// Fields following comm begin at field 3 (state). PPID is field 4 and
	// starttime is field 22 in proc(5), therefore indexes 1 and 19 here.
	if len(fields) <= 19 {
		return procStat{}, errors.New("incomplete proc stat")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return procStat{}, errors.New("invalid proc stat ppid")
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procStat{}, errors.New("invalid proc stat start time")
	}
	return procStat{pid: pid, ppid: ppid, startTicks: startTicks}, nil
}

// StartTimeTicks reads the PID reuse discriminator from a fixed /proc path.
// It is intentionally separate from PID-only lookup callers in other local
// collectors.
func StartTimeTicks(procRoot string, pid int) (uint64, error) {
	if pid <= 0 {
		return 0, errors.New("invalid pid")
	}
	content, err := readFileLimited(filepath.Join(procRoot, strconv.Itoa(pid), "stat"), maxProcStatBytes)
	if err != nil {
		return 0, err
	}
	stat, err := parseProcStat(string(content))
	if err != nil {
		return 0, err
	}
	if stat.pid != pid {
		return 0, errors.New("proc stat pid mismatch")
	}
	return stat.startTicks, nil
}

func parseProcStatus(content string) map[string]string {
	result := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 1024), maxProcStatusBytes)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result
}

func parseIDPair(value string) (uint32, uint32) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, 0
	}
	first, _ := strconv.ParseUint(fields[0], 10, 32)
	second := first
	if len(fields) > 1 {
		second, _ = strconv.ParseUint(fields[1], 10, 32)
	}
	return uint32(first), uint32(second)
}

func readCommandLine(path string, maximum int) (string, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	content, err := readAllLimited(file, int64(maximum))
	if err != nil {
		if errors.Is(err, errLimitExceeded) {
			return strings.TrimSpace(strings.ReplaceAll(string(content), "\x00", " ")), true, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(strings.ReplaceAll(string(content), "\x00", " ")), false, nil
}

func readNamespaces(base string) map[string]string {
	result := map[string]string{}
	for _, name := range []string{"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"} {
		if value, err := os.Readlink(filepath.Join(base, "ns", name)); err == nil && value != "" {
			result[name] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func capabilityFields(status map[string]string) map[string]string {
	result := map[string]string{}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if value := status[key]; value != "" {
			result[key] = value
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseContainerID(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		candidate := line
		if len(parts) == 3 {
			candidate = parts[2]
		}
		matches := containerIDPattern.FindStringSubmatch(candidate)
		if len(matches) == 2 {
			return strings.ToLower(matches[1])
		}
	}
	return ""
}

func executableIdentity(base string, maximum int64) (string, uint64, uint64) {
	path := filepath.Join(base, "exe")
	file, err := os.Open(path)
	if err != nil {
		return "", 0, 0
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, 0
	}
	inode, device := fileIdentity(info)
	if info.Size() < 0 || info.Size() > maximum {
		return "", inode, device
	}
	digest, err := hashReader(file, maximum)
	if err != nil {
		return "", inode, device
	}
	return digest, inode, device
}

func hashReader(reader io.Reader, maximum int64) (string, error) {
	digest := sha256.New()
	counting := &limitedHashReader{reader: reader, maximum: maximum}
	if _, err := io.Copy(hashWriter{Hash: digest}, counting); err != nil {
		return "", err
	}
	if counting.exceeded {
		return "", errLimitExceeded
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type hashWriter struct{ hash.Hash }

type limitedHashReader struct {
	reader   io.Reader
	maximum  int64
	read     int64
	exceeded bool
}

func (r *limitedHashReader) Read(destination []byte) (int, error) {
	if r.read > r.maximum {
		r.exceeded = true
		return 0, io.EOF
	}
	remaining := r.maximum - r.read + 1
	if int64(len(destination)) > remaining {
		destination = destination[:remaining]
	}
	count, err := r.reader.Read(destination)
	r.read += int64(count)
	if r.read > r.maximum {
		r.exceeded = true
	}
	return count, err
}

func readBootIDHash(procRoot string) (string, error) {
	value, err := readTrimmedLimited(filepath.Join(procRoot, "sys", "kernel", "random", "boot_id"), 256)
	if err != nil || value == "" {
		if err == nil {
			err = errors.New("empty boot identifier")
		}
		return "", err
	}
	digest := sha256.Sum256([]byte("linux-boot\x00" + value))
	return hex.EncodeToString(digest[:]), nil
}

func readBootTime(procRoot string) time.Time {
	content, err := readFileLimited(filepath.Join(procRoot, "stat"), maxProcStatusBytes)
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			seconds, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil && seconds > 0 {
				return time.Unix(seconds, 0).UTC()
			}
		}
	}
	return time.Time{}
}

func readClockTicks(procRoot string) uint64 {
	content, err := readFileLimited(filepath.Join(procRoot, "self", "auxv"), 4096)
	if err != nil {
		return 100
	}
	wordSize := 8
	if strconv.IntSize == 32 {
		wordSize = 4
	}
	for offset := 0; offset+wordSize*2 <= len(content); offset += wordSize * 2 {
		var key, value uint64
		if wordSize == 8 {
			key = binary.NativeEndian.Uint64(content[offset : offset+wordSize])
			value = binary.NativeEndian.Uint64(content[offset+wordSize : offset+wordSize*2])
		} else {
			key = uint64(binary.NativeEndian.Uint32(content[offset : offset+wordSize]))
			value = uint64(binary.NativeEndian.Uint32(content[offset+wordSize : offset+wordSize*2]))
		}
		if key == auxvClockTicks && value > 0 && value <= 100000 {
			return value
		}
	}
	return 100
}

func readFileLimited(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readAllLimited(file, int64(maximum))
}

var errLimitExceeded = errors.New("input exceeds configured limit")

func readAllLimited(reader io.Reader, maximum int64) ([]byte, error) {
	if maximum < 1 {
		return nil, errLimitExceeded
	}
	content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maximum {
		return content[:maximum], errLimitExceeded
	}
	return content, nil
}

func readTrimmedLimited(path string, maximum int) (string, error) {
	content, err := readFileLimited(path, maximum)
	return strings.TrimSpace(string(content)), err
}

func lookupUsername(uid uint32) string {
	entry, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil || entry.Username == "" {
		return "uid:" + strconv.FormatUint(uint64(uid), 10)
	}
	return entry.Username
}

func appendWarning(warnings *[]string, value string) {
	if len(*warnings) >= maxWarnings {
		return
	}
	*warnings = append(*warnings, value)
}

func boundedError(err error) string {
	value := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(value) > 160 {
		return value[:160]
	}
	return value
}
