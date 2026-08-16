package protection

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ruleManifestSchema = "ntagentshield-yarax-rules/v1"
	maxCapturedBytes   = 8 * 1024 * 1024
	maxYaraOutputBytes = 1024 * 1024
)

// This key is replaced only by a reviewed release. Tests can inject a key via
// Options.RulePublicKey. A rule file without a valid detached manifest is never
// considered authoritative.
const trustedRulePublicKeyBase64 = "GeMVpYno3lvs1e2mcXVuGYHh9XqHMD1gmexlTd8af/8="

type Options struct {
	YaraExecutable      string
	YaraRules           string
	YaraManifest        string
	RulePublicKey       ed25519.PublicKey
	HashDenylist        []string
	HashAllowlist       []string
	Exclusions          []string
	SuspiciousThreshold int
	MaliciousThreshold  int
	MaxFileBytes        int64
	ReputationEndpoint  string
	ReputationAPIKeyEnv string
	ReputationAPIKey    string
	ReputationTimeout   time.Duration
	ReputationCacheTTL  time.Duration
	RuleStateFile       string
}

type Scanner struct {
	options       Options
	deny          map[string]struct{}
	allow         map[string]struct{}
	exclusions    []string
	yaraEnabled   bool
	ruleVersion   string
	yaraError     string
	amsiAvailable bool
	reputation    *reputationClient
	healthMu      sync.RWMutex
	reputationErr string
}

type ruleManifest struct {
	Schema              string    `json:"schema"`
	Version             string    `json:"version"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	RulesSHA256         string    `json:"rules_sha256"`
	MinimumAgentVersion string    `json:"minimum_agent_version,omitempty"`
	Signature           string    `json:"signature"`
}

func NewScanner(options Options) (*Scanner, error) {
	if options.SuspiciousThreshold == 0 {
		options.SuspiciousThreshold = 70
	}
	if options.MaliciousThreshold == 0 {
		options.MaliciousThreshold = 95
	}
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = 128 * 1024 * 1024
	}
	s := &Scanner{options: options, deny: stringSet(options.HashDenylist), allow: stringSet(options.HashAllowlist)}
	for _, path := range options.Exclusions {
		if absolute, err := filepath.Abs(path); err == nil {
			s.exclusions = append(s.exclusions, strings.ToLower(filepath.Clean(absolute)))
		}
	}
	_, amsiErr := scanAMSI(context.Background(), "health-check.txt", []byte("NTAgentShield health check"))
	s.amsiAvailable = amsiErr == nil
	if options.ReputationEndpoint != "" {
		reputation, err := newReputationClient(options.ReputationEndpoint, options.ReputationAPIKeyEnv, options.ReputationTimeout, options.ReputationCacheTTL, options.ReputationAPIKey)
		if err != nil {
			return nil, err
		}
		s.reputation = reputation
	}
	if options.YaraExecutable != "" || options.YaraRules != "" || options.YaraManifest != "" {
		manifest, err := verifyRuleBundle(options)
		if err != nil {
			s.yaraError = err.Error()
		} else {
			if options.RuleStateFile != "" {
				if err := acceptRuleVersion(options.RuleStateFile, manifest.Version); err != nil {
					s.yaraError = err.Error()
					return s, nil
				}
			}
			s.yaraEnabled = true
			s.ruleVersion = manifest.Version
		}
	}
	return s, nil
}

type ruleVersionState struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}

func acceptRuleVersion(path, version string) error {
	newVersion, err := numericRuleVersion(version)
	if err != nil {
		return err
	}
	content, readErr := os.ReadFile(path)
	if readErr == nil {
		var state ruleVersionState
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&state); err != nil || state.Schema != "ntagentshield-rule-state/v1" {
			return errors.New("accepted rule version state is invalid")
		}
		currentVersion, err := numericRuleVersion(state.Version)
		if err != nil {
			return errors.New("accepted rule version state contains an invalid version")
		}
		comparison := compareNumericVersion(newVersion, currentVersion)
		if comparison < 0 {
			return fmt.Errorf("YARA-X rule downgrade rejected: %s is older than %s", version, state.Version)
		}
		if comparison == 0 {
			return nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read accepted rule version state: %w", readErr)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(ruleVersionState{Schema: "ntagentshield-rule-state/v1", Version: version}, "", "  ")
	encoded = append(encoded, '\n')
	temporary := path + ".new"
	backup := path + ".bak"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(temporary, 0o600)
	_ = os.Remove(backup)
	hadExisting := false
	if _, err := os.Stat(path); err == nil {
		hadExisting = true
		if err := os.Rename(path, backup); err != nil {
			_ = os.Remove(temporary)
			return err
		}
	}
	if err := os.Rename(temporary, path); err != nil {
		if hadExisting {
			_ = os.Rename(backup, path)
		}
		_ = os.Remove(temporary)
		return err
	}
	if hadExisting {
		_ = os.Remove(backup)
	}
	return nil
}

func numericRuleVersion(version string) ([]int, error) {
	if !regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}\.\d+$`).MatchString(version) {
		return nil, fmt.Errorf("YARA-X rule version %q is not numeric and monotonic", version)
	}
	parts := strings.Split(version, ".")
	result := make([]int, len(parts))
	for index, part := range parts {
		result[index], _ = strconv.Atoi(part)
	}
	return result, nil
}

func compareNumericVersion(left, right []int) int {
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func (s *Scanner) Health() (bool, string, bool, string, bool, string) {
	s.healthMu.RLock()
	defer s.healthMu.RUnlock()
	return s.yaraEnabled, s.ruleVersion, s.amsiAvailable, s.yaraError, s.reputation != nil, s.reputationErr
}

func (s *Scanner) ScanFile(ctx context.Context, path string, maximum int64) (Verdict, error) {
	verdict := Verdict{ID: newVerdictID(path), Path: path, ScannedAt: time.Now().UTC(), Disposition: DispositionUnknown, RuleVersion: s.ruleVersion}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return verdict, err
	}
	absolute = filepath.Clean(absolute)
	verdict.Path = absolute
	if s.excluded(absolute) {
		verdict.SkippedReason = "excluded"
		return verdict, nil
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return verdict, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		verdict.SkippedReason = "not_regular_file"
		return verdict, nil
	}
	if maximum <= 0 {
		maximum = s.options.MaxFileBytes
	}
	verdict.Size = info.Size()
	if info.Size() > maximum {
		verdict.SkippedReason = "size_limit"
		return verdict, nil
	}
	file, err := os.Open(absolute)
	if err != nil {
		return verdict, err
	}
	defer file.Close()
	hasher := sha256.New()
	captured := &boundedBuffer{maximum: maxCapturedBytes}
	written, err := io.Copy(io.MultiWriter(hasher, captured), file)
	if err != nil {
		return verdict, err
	}
	if written != info.Size() {
		return verdict, errors.New("file changed or was truncated while scanning")
	}
	verdict.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	if _, ok := s.allow[verdict.SHA256]; ok {
		verdict.Signals = append(verdict.Signals, Signal{Source: "local_hash", ID: "allowlist", Confidence: 100, Detail: "signed local allowlist"})
		verdict.Score = 0
		verdict.Disposition = DispositionClean
		return verdict, nil
	}
	if _, ok := s.deny[verdict.SHA256]; ok {
		verdict.Signals = append(verdict.Signals, Signal{Source: "local_hash", ID: "denylist", Confidence: 100, Authoritative: true})
	}
	if s.reputation != nil {
		if signal, reputationErr := s.reputation.lookup(ctx, verdict.SHA256); reputationErr != nil {
			s.healthMu.Lock()
			s.reputationErr = reputationErr.Error()
			s.healthMu.Unlock()
		} else {
			s.healthMu.Lock()
			s.reputationErr = ""
			s.healthMu.Unlock()
			if signal != nil {
				verdict.Signals = append(verdict.Signals, *signal)
			}
		}
	}
	content := captured.content
	verdict.Signals = append(verdict.Signals, nativeSignals(absolute, content)...)
	if result, amsiErr := scanAMSI(ctx, absolute, content); amsiErr == nil && result.Malware {
		verdict.Signals = append(verdict.Signals, Signal{Source: "amsi", ID: result.Name, Confidence: 100, Authoritative: true})
	}
	if s.yaraEnabled {
		signals, yaraErr := s.scanYara(ctx, absolute)
		if yaraErr != nil {
			return verdict, fmt.Errorf("YARA-X scan: %w", yaraErr)
		}
		verdict.Signals = append(verdict.Signals, signals...)
	}
	for _, signal := range verdict.Signals {
		if signal.Confidence > verdict.Score {
			verdict.Score = signal.Confidence
		}
		if signal.Authoritative {
			verdict.Authoritative = true
		}
	}
	switch {
	case verdict.Score >= s.options.MaliciousThreshold && verdict.Authoritative:
		verdict.Disposition = DispositionMalicious
	case verdict.Score >= s.options.SuspiciousThreshold:
		verdict.Disposition = DispositionSuspicious
	case len(verdict.Signals) == 0:
		verdict.Disposition = DispositionClean
	default:
		verdict.Disposition = DispositionUnknown
	}
	return verdict, nil
}

func (s *Scanner) excluded(path string) bool {
	path = strings.ToLower(filepath.Clean(path))
	for _, root := range s.exclusions {
		relative, err := filepath.Rel(root, path)
		if err == nil && (relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			return true
		}
	}
	return false
}

func nativeSignals(path string, content []byte) []Signal {
	lower := bytes.ToLower(content)
	signals := []Signal{}
	if bytes.Contains(content, []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")) {
		return []Signal{{Source: "native", ID: "eicar_test_file", Confidence: 100, Authoritative: true}}
	}
	patterns := []struct {
		id    string
		text  []byte
		score int
	}{
		{"encoded_powershell", []byte("-encodedcommand"), 82},
		{"powershell_download", []byte("downloadstring("), 88},
		{"powershell_iex", []byte("invoke-expression"), 82},
		{"base64_decode", []byte("frombase64string"), 50},
		{"credential_dump", []byte("sekurlsa::logonpasswords"), 98},
	}
	for _, pattern := range patterns {
		if bytes.Contains(lower, pattern.text) {
			signals = append(signals, Signal{Source: "native", ID: pattern.id, Confidence: pattern.score})
		}
	}
	extension := strings.ToLower(filepath.Ext(path))
	if extension == ".exe" || extension == ".dll" || extension == ".sys" || extension == ".scr" {
		if entropy(content) >= 7.4 {
			signals = append(signals, Signal{Source: "native", ID: "high_entropy_pe", Confidence: 60})
		}
		if file, err := pe.Open(path); err == nil {
			defer file.Close()
			if len(file.Sections) > 12 {
				signals = append(signals, Signal{Source: "native", ID: "unusual_pe_sections", Confidence: 60})
			}
		}
	}
	if regexp.MustCompile(`(?i)\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|com)$`).MatchString(filepath.Base(path)) {
		signals = append(signals, Signal{Source: "native", ID: "double_extension_executable", Confidence: 86})
	}
	return signals
}

func entropy(content []byte) float64 {
	if len(content) == 0 {
		return 0
	}
	var counts [256]int
	for _, value := range content {
		counts[value]++
	}
	result := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(content))
		result -= probability * math.Log2(probability)
	}
	return result
}

func (s *Scanner) scanYara(ctx context.Context, path string) ([]Signal, error) {
	command := exec.CommandContext(ctx, s.options.YaraExecutable, "scan", "--output-format=ndjson", "-m", "-g", s.options.YaraRules, path)
	output := &boundedBuffer{maximum: maxYaraOutputBytes}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(output.String()))
	}
	if output.exceeded {
		return nil, errors.New("output exceeded 1 MiB")
	}
	signals := []Signal{}
	scanner := bufio.NewScanner(bytes.NewReader(output.content))
	for scanner.Scan() {
		var item struct {
			Rules []struct {
				Identifier string          `json:"identifier"`
				Tags       []string        `json:"tags"`
				Meta       [][]interface{} `json:"meta"`
			} `json:"rules"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return nil, fmt.Errorf("decode NDJSON: %w", err)
		}
		for _, rule := range item.Rules {
			action := "alert"
			for _, item := range rule.Meta {
				if len(item) == 2 && strings.EqualFold(fmt.Sprint(item[0]), "action") {
					action = strings.ToLower(strings.TrimSpace(fmt.Sprint(item[1])))
				}
			}
			signal := Signal{Source: "yara_x", ID: rule.Identifier, Confidence: 65, Detail: strings.Join(rule.Tags, ",")}
			if action == "block" {
				signal.Confidence = 100
				signal.Authoritative = true
			}
			signals = append(signals, signal)
		}
	}
	return signals, scanner.Err()
}

func verifyRuleBundle(options Options) (ruleManifest, error) {
	if options.YaraExecutable == "" || options.YaraRules == "" || options.YaraManifest == "" {
		return ruleManifest{}, errors.New("YARA-X executable, rules, and manifest must all be configured")
	}
	for _, path := range []string{options.YaraExecutable, options.YaraRules, options.YaraManifest} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			return ruleManifest{}, fmt.Errorf("required YARA-X file is unavailable: %s", path)
		}
	}
	content, err := os.ReadFile(options.YaraManifest)
	if err != nil {
		return ruleManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest ruleManifest
	if err := decoder.Decode(&manifest); err != nil {
		return ruleManifest{}, err
	}
	if manifest.Schema != ruleManifestSchema || manifest.Version == "" || manifest.ExpiresAt.Before(time.Now().UTC()) {
		return ruleManifest{}, errors.New("rule manifest schema, version, or expiry is invalid")
	}
	digest, err := hashFile(options.YaraRules)
	if err != nil || !strings.EqualFold(digest, manifest.RulesSHA256) {
		return ruleManifest{}, errors.New("YARA-X rules digest does not match manifest")
	}
	publicKey := options.RulePublicKey
	if len(publicKey) == 0 {
		decoded, decodeErr := base64.StdEncoding.DecodeString(trustedRulePublicKeyBase64)
		if decodeErr != nil {
			return ruleManifest{}, decodeErr
		}
		publicKey = ed25519.PublicKey(decoded)
	}
	signature, err := base64.StdEncoding.DecodeString(manifest.Signature)
	if err != nil {
		return ruleManifest{}, errors.New("rule manifest signature is invalid base64")
	}
	manifest.Signature = ""
	unsigned, _ := json.Marshal(manifest)
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, unsigned, signature) {
		return ruleManifest{}, errors.New("rule manifest signature verification failed")
	}
	return manifest, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type boundedBuffer struct {
	content  []byte
	maximum  int
	exceeded bool
}

func (b *boundedBuffer) Write(content []byte) (int, error) {
	remaining := b.maximum - len(b.content)
	if remaining <= 0 {
		b.exceeded = true
		return len(content), nil
	}
	if len(content) > remaining {
		b.content = append(b.content, content[:remaining]...)
		b.exceeded = true
		return len(content), nil
	}
	b.content = append(b.content, content...)
	return len(content), nil
}

func (b *boundedBuffer) String() string { return string(b.content) }

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if len(value) == 64 {
			if _, err := hex.DecodeString(value); err == nil {
				result[value] = struct{}{}
			}
		}
	}
	return result
}

func newVerdictID(path string) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", path, time.Now().UTC().UnixNano())))
	return "vrd_" + hex.EncodeToString(digest[:16])
}
