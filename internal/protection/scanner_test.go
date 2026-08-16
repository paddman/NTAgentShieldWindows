package protection

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeDetectsEICARAuthoritatively(t *testing.T) {
	content := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	signals := nativeSignals("eicar.com", content)
	if len(signals) != 1 || !signals[0].Authoritative || signals[0].Confidence != 100 || signals[0].ID != "eicar_test_file" {
		t.Fatalf("unexpected EICAR signals: %#v", signals)
	}
}

func TestScannerHashDenylistIsAuthoritative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "denylisted.exe")
	content := []byte("harmless test fixture whose hash is locally denied")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	scanner, err := NewScanner(Options{SuspiciousThreshold: 70, MaliciousThreshold: 95, HashDenylist: []string{hex.EncodeToString(digest[:])}})
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := scanner.ScanFile(context.Background(), path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Disposition != DispositionMalicious || !verdict.Authoritative || verdict.Score != 100 {
		t.Fatalf("unexpected denylist verdict: %#v", verdict)
	}
}

func TestHeuristicSignalDoesNotAutoPromoteWithoutAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invoice.pdf.exe")
	if err := os.WriteFile(path, []byte("powershell -EncodedCommand AAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner, _ := NewScanner(Options{SuspiciousThreshold: 70, MaliciousThreshold: 95})
	verdict, err := scanner.ScanFile(context.Background(), path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Disposition != DispositionSuspicious || verdict.Authoritative {
		t.Fatalf("heuristics bypassed the authoritative gate: %#v", verdict)
	}
}

func TestSignedRuleManifestRejectsTampering(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "yr.exe")
	rules := filepath.Join(directory, "rules.yar")
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(executable, []byte("placeholder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte("rule safe { condition: false }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := hashFile(rules)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ruleManifest{Schema: ruleManifestSchema, Version: "test-1", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(), RulesSHA256: digest}
	unsigned, _ := json.Marshal(manifest)
	manifest.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, unsigned))
	encoded, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{YaraExecutable: executable, YaraRules: rules, YaraManifest: manifestPath, RulePublicKey: publicKey}
	if _, err := verifyRuleBundle(options); err != nil {
		t.Fatalf("valid signed rule bundle was rejected: %v", err)
	}
	if err := os.WriteFile(rules, []byte("rule changed { condition: true }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRuleBundle(options); err == nil {
		t.Fatal("tampered YARA-X rules were accepted")
	}
}

func TestPackagedRuleManifestUsesTrustedReleaseKey(t *testing.T) {
	rules := filepath.Join("..", "..", "rules", "windows", "default.yar")
	manifest := filepath.Join("..", "..", "rules", "windows", "default.manifest.json")
	if _, err := verifyRuleBundle(Options{YaraExecutable: os.Args[0], YaraRules: rules, YaraManifest: manifest}); err != nil {
		t.Fatalf("packaged signed rule bundle was rejected: %v", err)
	}
}

func TestRuleVersionStateRejectsDowngrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule-version.json")
	if err := acceptRuleVersion(path, "2026.08.16.2"); err != nil {
		t.Fatal(err)
	}
	if err := acceptRuleVersion(path, "2026.08.16.1"); err == nil {
		t.Fatal("signed rule downgrade was accepted")
	}
	if err := acceptRuleVersion(path, "2026.08.17.1"); err != nil {
		t.Fatalf("newer rule version was rejected: %v", err)
	}
}
