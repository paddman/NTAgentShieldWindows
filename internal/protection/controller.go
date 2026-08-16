package protection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/identity"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/tools"
)

type Outcome struct {
	Verdict Verdict                  `json:"verdict"`
	Event   *model.Event             `json:"event,omitempty"`
	Finding *model.Finding           `json:"finding,omitempty"`
	Actions []map[string]interface{} `json:"actions,omitempty"`
}

type Controller struct {
	cfg            config.Config
	scanner        *Scanner
	quarantine     *tools.FileQuarantine
	logger         *log.Logger
	auditStartedAt time.Time
	auditPeriod    time.Duration
	quickInterval  time.Duration
	fullInterval   time.Duration
	scanTimeout    time.Duration
	mu             sync.RWMutex
	recentScans    []ScanSummary
	lastScan       *ScanSummary
	cache          map[string]cachedVerdict
	scans          atomic.Uint64
	files          atomic.Uint64
	suspicious     atomic.Uint64
	malicious      atomic.Uint64
	quarantined    atomic.Uint64
	killed         atomic.Uint64
	errors         atomic.Uint64
	lastScanNano   atomic.Int64
	scanRunning    atomic.Bool
	currentScanID  atomic.Value
}

type cachedVerdict struct {
	Size       int64
	ModifiedAt time.Time
	ExpiresAt  time.Time
	Verdict    Verdict
}

type protectionState struct {
	Schema         string    `json:"schema"`
	AuditStartedAt time.Time `json:"audit_started_at"`
}

func NewController(cfg config.Config, logger *log.Logger) (*Controller, error) {
	if runtime.GOOS != "windows" || !cfg.Protection.Enabled || !cfg.Scanner.Enabled {
		return nil, nil
	}
	auditPeriod, _ := time.ParseDuration(cfg.Protection.AuditPeriod)
	quickInterval, _ := time.ParseDuration(cfg.Scanner.QuickInterval)
	fullInterval, _ := time.ParseDuration(cfg.Scanner.FullInterval)
	scanTimeout, _ := time.ParseDuration(cfg.Scanner.ScanTimeout)
	reputationTimeout, _ := time.ParseDuration(cfg.Reputation.Timeout)
	reputationTTL, _ := time.ParseDuration(cfg.Reputation.CacheTTL)
	reputationEndpoint := ""
	if cfg.Reputation.Enabled {
		reputationEndpoint = cfg.Reputation.Endpoint
	}
	scanner, err := NewScanner(Options{
		YaraExecutable: cfg.Scanner.YaraExecutable, YaraRules: cfg.Scanner.YaraRules, YaraManifest: cfg.Scanner.YaraManifest,
		HashDenylist: cfg.Scanner.HashDenylist, HashAllowlist: cfg.Scanner.HashAllowlist, Exclusions: cfg.Protection.Exclusions,
		SuspiciousThreshold: cfg.Protection.SuspiciousThreshold, MaliciousThreshold: cfg.Protection.MaliciousThreshold,
		MaxFileBytes:       cfg.Scanner.MaxAutomaticFileBytes,
		RuleStateFile:      filepath.Join(cfg.DataDir, "accepted-rule-version.json"),
		ReputationEndpoint: reputationEndpoint, ReputationAPIKeyEnv: cfg.Reputation.APIKeyEnv,
		ReputationAPIKey: os.Getenv(cfg.Reputation.APIKeyEnv), ReputationTimeout: reputationTimeout, ReputationCacheTTL: reputationTTL,
	})
	if err != nil {
		return nil, err
	}
	_, keyPath, err := identity.Ensure(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	quarantine, err := tools.NewFileQuarantine(cfg.Protection.ProtectedPaths, cfg.DataDir, keyPath)
	if err != nil {
		return nil, err
	}
	started, err := ensureProtectionState(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return &Controller{
		cfg: cfg, scanner: scanner, quarantine: quarantine, logger: logger,
		auditStartedAt: started, auditPeriod: auditPeriod, quickInterval: quickInterval,
		fullInterval: fullInterval, scanTimeout: scanTimeout, cache: map[string]cachedVerdict{},
	}, nil
}

func (c *Controller) Run(ctx context.Context, emit func(Outcome)) {
	quick := time.NewTicker(c.quickInterval)
	full := time.NewTicker(c.fullInterval)
	defer quick.Stop()
	defer full.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-quick.C:
			_, _ = c.StartScan(ctx, "quick", emit)
		case <-full.C:
			_, _ = c.StartScan(ctx, "full", emit)
		}
	}
}

// StartScan schedules one bounded scan. Overlapping scans are rejected so a
// local caller cannot multiply disk and CPU pressure on a server.
func (c *Controller) StartScan(ctx context.Context, profile string, emit func(Outcome)) (string, error) {
	if c == nil {
		return "", errors.New("malware protection is disabled")
	}
	var paths []string
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "quick":
		profile = "quick"
		paths = append([]string(nil), c.cfg.Scanner.QuickPaths...)
	case "full":
		profile = "full"
		paths = fixedVolumeRoots()
	default:
		return "", errors.New("scan profile must be quick or full")
	}
	if !c.scanRunning.CompareAndSwap(false, true) {
		return "", errors.New("a malware scan is already running")
	}
	id := newVerdictID(profile)
	c.currentScanID.Store(id)
	go func() {
		defer c.scanRunning.Store(false)
		c.scanPathsWithID(ctx, id, profile, paths, emit)
	}()
	return id, nil
}

func (c *Controller) InspectEvent(ctx context.Context, event model.Event) (Outcome, bool, error) {
	if c == nil || event.Kind != "process.start" || event.Process.Image == "" {
		return Outcome{}, false, nil
	}
	if !scannableExtension(event.Process.Image) {
		return Outcome{}, false, nil
	}
	verdict, err := c.scanCached(ctx, event.Process.Image, c.cfg.Scanner.MaxAutomaticFileBytes)
	if err != nil {
		c.errors.Add(1)
		return Outcome{}, false, err
	}
	c.files.Add(1)
	outcome := c.outcome(event, verdict)
	if verdict.Disposition != DispositionSuspicious && verdict.Disposition != DispositionMalicious {
		return outcome, false, nil
	}
	if verdict.Disposition == DispositionSuspicious {
		c.suspicious.Add(1)
	} else {
		c.malicious.Add(1)
	}
	if verdict.Disposition == DispositionMalicious && c.enforcementReady() && c.cfg.Protection.Mode == "enforce" {
		c.enforce(ctx, event, &outcome)
	}
	return outcome, true, nil
}

func (c *Controller) ScanNow(ctx context.Context, profile string, paths []string, emit func(Outcome)) ScanSummary {
	return c.scanPathsWithID(ctx, newVerdictID(profile), profile, paths, emit)
}

func (c *Controller) scanPaths(ctx context.Context, profile string, paths []string, emit func(Outcome)) ScanSummary {
	return c.scanPathsWithID(ctx, newVerdictID(profile), profile, paths, emit)
}

func (c *Controller) scanPathsWithID(ctx context.Context, id, profile string, paths []string, emit func(Outcome)) ScanSummary {
	summary := ScanSummary{ID: id, Profile: profile, StartedAt: time.Now().UTC(), Running: true}
	c.scans.Add(1)
	maximum := c.cfg.Scanner.MaxScheduledFileBytes
	type scanResult struct {
		verdict Verdict
		err     error
	}
	jobs := make(chan string, c.cfg.Scanner.Workers*2)
	results := make(chan scanResult, c.cfg.Scanner.Workers*2)
	var workers sync.WaitGroup
	for i := 0; i < c.cfg.Scanner.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for path := range jobs {
				scanCtx, cancel := context.WithTimeout(ctx, c.scanTimeout)
				verdict, err := c.scanner.ScanFile(scanCtx, path, maximum)
				cancel()
				results <- scanResult{verdict: verdict, err: err}
			}
		}()
	}
	go func() {
		seen := 0
		for _, root := range paths {
			if ctx.Err() != nil || seen >= c.cfg.Scanner.MaxFilesPerScan {
				break
			}
			walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					results <- scanResult{err: err}
					return nil
				}
				if ctx.Err() != nil || seen >= c.cfg.Scanner.MaxFilesPerScan {
					return filepath.SkipAll
				}
				if entry.Type()&os.ModeSymlink != 0 {
					if entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				if entry.IsDir() || !scannableExtension(path) {
					return nil
				}
				seen++
				select {
				case jobs <- path:
					return nil
				case <-ctx.Done():
					return filepath.SkipAll
				}
			})
			if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
				results <- scanResult{err: walkErr}
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	for result := range results {
		if result.err != nil {
			summary.Errors++
			c.errors.Add(1)
			continue
		}
		verdict := result.verdict
		if verdict.SkippedReason != "" {
			summary.Skipped++
			continue
		}
		summary.Files++
		c.files.Add(1)
		if verdict.Disposition == DispositionSuspicious {
			summary.Suspicious++
			c.suspicious.Add(1)
		}
		if verdict.Disposition == DispositionMalicious {
			summary.Malicious++
			c.malicious.Add(1)
		}
		if emit != nil && (verdict.Disposition == DispositionSuspicious || verdict.Disposition == DispositionMalicious) {
			source := model.Event{Timestamp: time.Now().UTC(), Kind: "file.scan", Trust: model.TrustSystem, File: model.FileContext{Path: verdict.Path, SHA256: verdict.SHA256, Size: verdict.Size}}
			outcome := c.outcome(source, verdict)
			if verdict.Disposition == DispositionMalicious && c.enforcementReady() && c.cfg.Protection.Mode == "enforce" {
				c.enforce(ctx, source, &outcome)
			}
			emit(outcome)
		}
	}
	summary.CompletedAt = time.Now().UTC()
	summary.Running = false
	c.lastScanNano.Store(summary.CompletedAt.UnixNano())
	c.mu.Lock()
	c.lastScan = &summary
	c.recentScans = append([]ScanSummary{summary}, c.recentScans...)
	if len(c.recentScans) > 20 {
		c.recentScans = c.recentScans[:20]
	}
	c.mu.Unlock()
	return summary
}

func (c *Controller) scanCached(ctx context.Context, path string, maximum int64) (Verdict, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Verdict{}, err
	}
	key := strings.ToLower(filepath.Clean(path))
	c.mu.RLock()
	cached, exists := c.cache[key]
	c.mu.RUnlock()
	if exists && time.Now().Before(cached.ExpiresAt) && cached.Size == info.Size() && cached.ModifiedAt.Equal(info.ModTime()) {
		return cached.Verdict, nil
	}
	scanCtx, cancel := context.WithTimeout(ctx, c.scanTimeout)
	defer cancel()
	verdict, err := c.scanner.ScanFile(scanCtx, path, maximum)
	if err == nil {
		c.mu.Lock()
		if len(c.cache) >= 4096 {
			c.cache = map[string]cachedVerdict{}
		}
		c.cache[key] = cachedVerdict{Size: info.Size(), ModifiedAt: info.ModTime(), ExpiresAt: time.Now().Add(5 * time.Minute), Verdict: verdict}
		c.mu.Unlock()
	}
	return verdict, err
}

func (c *Controller) outcome(source model.Event, verdict Verdict) Outcome {
	severity := model.SeverityHigh
	if verdict.Disposition == DispositionMalicious {
		severity = model.SeverityCritical
	}
	event := model.Event{
		Timestamp: verdict.ScannedAt, Kind: "malware.verdict", Severity: severity, Trust: model.TrustUntrustedCode,
		Asset: source.Asset, Process: source.Process,
		File:       model.FileContext{Path: verdict.Path, SHA256: verdict.SHA256, Size: verdict.Size, Executable: scannableExtension(verdict.Path)},
		Message:    fmt.Sprintf("local malware scan classified file as %s", verdict.Disposition),
		Attributes: map[string]interface{}{"protection": verdict},
		Provenance: model.Provenance{Source: "windows-protection", Collector: "local-ngav"},
	}
	event.Prepare()
	finding := model.NewFinding(event, "NGAV-"+strings.ToUpper(string(verdict.Disposition)), "Malware protection verdict", "Local deterministic scanners classified a file for investigation or containment.", "malware", severity, verdict.Score)
	finding.TitleTH = "ผลตรวจมัลแวร์จากระบบป้องกัน"
	finding.DescriptionTH = "ตัวตรวจแบบ deterministic บนเครื่องจัดประเภทไฟล์ว่าต้องตรวจสอบหรือกักกัน"
	finding.RecommendedResponse = "file.quarantine"
	finding.RecommendedSteps = []string{"Review scanner signals and file signer", "Confirm process ancestry and network activity", "Keep containment reversible"}
	return Outcome{Verdict: verdict, Event: &event, Finding: &finding}
}

func (c *Controller) enforce(ctx context.Context, source model.Event, outcome *Outcome) {
	if isProtectedWindowsPath(outcome.Verdict.Path) {
		outcome.Actions = append(outcome.Actions, map[string]interface{}{"action": "blocked", "reason": "protected_windows_path_requires_approval"})
		return
	}
	if c.cfg.Protection.AutoKill && source.Process.PID > 4 {
		if result, err := tools.TerminateVerifiedProcess(ctx, source.Process.PID, source.Process.Image); err == nil {
			result["action"] = "process.terminate"
			outcome.Actions = append(outcome.Actions, result)
			c.killed.Add(1)
		} else {
			outcome.Actions = append(outcome.Actions, map[string]interface{}{"action": "process.terminate", "error": err.Error()})
			c.errors.Add(1)
		}
	}
	if c.cfg.Protection.AutoQuarantine {
		result, err := c.quarantine.Execute(ctx, map[string]interface{}{"path": outcome.Verdict.Path, "expected_sha256": outcome.Verdict.SHA256})
		if err != nil {
			outcome.Actions = append(outcome.Actions, map[string]interface{}{"action": "file.quarantine", "error": err.Error()})
			c.errors.Add(1)
		} else if typed, ok := result.(map[string]interface{}); ok {
			typed["action"] = "file.quarantine"
			outcome.Actions = append(outcome.Actions, typed)
			c.quarantined.Add(1)
		}
	}
}

func (c *Controller) Status() Status {
	yaraEnabled, ruleVersion, amsiAvailable, yaraError, reputationEnabled, reputationError := c.scanner.Health()
	status := Status{
		Enabled: true, Mode: c.cfg.Protection.Mode, AuditStartedAt: c.auditStartedAt,
		AuditReadyAt: c.auditStartedAt.Add(c.auditPeriod), EnforcementReady: c.enforcementReady(),
		YaraEnabled: yaraEnabled, YaraRuleVersion: ruleVersion, AMSIAvailable: amsiAvailable,
		ReputationEnabled: reputationEnabled,
		Scans:             c.scans.Load(), FilesScanned: c.files.Load(), Suspicious: c.suspicious.Load(), Malicious: c.malicious.Load(),
		Quarantined: c.quarantined.Load(), Killed: c.killed.Load(), Errors: c.errors.Load(),
	}
	status.ScanRunning = c.scanRunning.Load()
	if value := c.currentScanID.Load(); value != nil {
		status.CurrentScanID, _ = value.(string)
	}
	if yaraError != "" {
		status.DegradedReasons = append(status.DegradedReasons, "YARA-X: "+yaraError)
	}
	if !amsiAvailable {
		status.DegradedReasons = append(status.DegradedReasons, "AMSI unavailable")
	}
	if reputationError != "" {
		status.DegradedReasons = append(status.DegradedReasons, "hash reputation: "+reputationError)
	}
	if value := c.lastScanNano.Load(); value != 0 {
		last := time.Unix(0, value).UTC()
		status.LastScanAt = &last
	}
	c.mu.RLock()
	if c.lastScan != nil {
		copy := *c.lastScan
		status.LastScan = &copy
	}
	status.RecentScans = append([]ScanSummary(nil), c.recentScans...)
	c.mu.RUnlock()
	return status
}

func (c *Controller) enforcementReady() bool {
	return !c.auditStartedAt.IsZero() && !time.Now().Before(c.auditStartedAt.Add(c.auditPeriod))
}

func ensureProtectionState(dataDir string) (time.Time, error) {
	path := filepath.Join(dataDir, "protection-state.json")
	content, err := os.ReadFile(path)
	if err == nil {
		var state protectionState
		if json.Unmarshal(content, &state) == nil && state.Schema == "ntagentshield-protection/v1" && !state.AuditStartedAt.IsZero() {
			return state.AuditStartedAt.UTC(), os.Chmod(path, 0o600)
		}
		return time.Time{}, errors.New("protection state is invalid")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return time.Time{}, err
	}
	state := protectionState{Schema: "ntagentshield-protection/v1", AuditStartedAt: time.Now().UTC()}
	encoded, _ := json.MarshalIndent(state, "", "  ")
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return time.Time{}, err
	}
	return state.AuditStartedAt, nil
}

func scannableExtension(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".dll", ".sys", ".scr", ".com", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".hta", ".msi", ".jar":
		return true
	default:
		return false
	}
}

func isProtectedWindowsPath(path string) bool {
	path = strings.ToLower(filepath.Clean(path))
	for _, root := range []string{os.Getenv("SystemRoot"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if root == "" {
			continue
		}
		relative, err := filepath.Rel(strings.ToLower(filepath.Clean(root)), path)
		if err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}

func fixedVolumeRoots() []string {
	if runtime.GOOS == "windows" {
		if drive := os.Getenv("SystemDrive"); drive != "" {
			return []string{drive + string(os.PathSeparator)}
		}
	}
	return []string{string(os.PathSeparator)}
}
