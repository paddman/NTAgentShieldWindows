package filetail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paddman/NTAgentShieldWindows/internal/config"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestTailerReadsOnlyCompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	if err := os.WriteFile(path, []byte("first\npartial"), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := New(config.Source{ID: "test", Path: path, Format: "raw", Trust: model.TrustUntrustedTelemetry, FromStart: true, MaxBatch: 100})
	if err != nil {
		t.Fatal(err)
	}
	events, errs := tailer.Poll()
	if len(errs) != 0 || len(events) != 1 || events[0].Message != "first" {
		t.Fatalf("unexpected first poll: events=%+v errors=%+v", events, errs)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("-line\n")
	_ = file.Close()
	events, errs = tailer.Poll()
	if len(errs) != 0 || len(events) != 1 || events[0].Message != "partial-line" {
		t.Fatalf("unexpected second poll: events=%+v errors=%+v", events, errs)
	}
}

func TestTailerIISPrimesHeaderWhenStartingAtEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u_ex260816.log")
	initial := "#Software: Microsoft Internet Information Services 10.0\n#Fields: date time c-ip cs-method cs-uri-stem sc-status time-taken\n2026-08-16 13:00:00 192.0.2.10 GET /old 200 4\n"
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := New(config.Source{ID: "iis-sites", Path: path, Format: "iis_w3c", Trust: model.TrustUntrustedTelemetry, FromStart: false, MaxBatch: 100})
	if err != nil {
		t.Fatal(err)
	}
	if events, errs := tailer.Poll(); len(errs) != 0 || len(events) != 0 {
		t.Fatalf("initial poll replayed data: events=%+v errors=%+v", events, errs)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("2026-08-16 13:00:01 198.51.100.20 POST /new 201 9\n")
	_ = file.Close()
	events, errs := tailer.Poll()
	if len(errs) != 0 || len(events) != 1 || events[0].HTTP.Path != "/new" || events[0].Network.SourceIP != "198.51.100.20" {
		t.Fatalf("unexpected primed IIS poll: events=%+v errors=%+v", events, errs)
	}
}

func TestTailerIISGlobKeepsSchemaPerSite(t *testing.T) {
	root := t.TempDir()
	paths := []struct {
		dir, content string
	}{
		{"W3SVC1", "#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-08-16 13:00:00 192.0.2.1 GET /one 200\n"},
		{"W3SVC2", "#Fields: date time cs-method cs-uri-stem c-ip sc-status\n2026-08-16 13:00:01 POST /two 198.51.100.2 202\n"},
	}
	for _, item := range paths {
		dir := filepath.Join(root, item.dir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "u_ex260816.log"), []byte(item.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tailer, err := New(config.Source{ID: "iis-sites", Path: filepath.Join(root, "W3SVC*", "u_ex*.log"), Format: "iis_w3c", Trust: model.TrustUntrustedTelemetry, FromStart: true, MaxBatch: 100})
	if err != nil {
		t.Fatal(err)
	}
	events, errs := tailer.Poll()
	if len(errs) != 0 || len(events) != 2 {
		t.Fatalf("unexpected IIS glob poll: events=%+v errors=%+v", events, errs)
	}
	if events[0].HTTP.Path != "/one" || events[0].Network.SourceIP != "192.0.2.1" || events[1].HTTP.Path != "/two" || events[1].Network.SourceIP != "198.51.100.2" {
		t.Fatalf("IIS schemas crossed between sites: %+v", events)
	}
}
