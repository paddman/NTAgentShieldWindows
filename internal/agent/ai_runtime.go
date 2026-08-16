package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/ai"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/redact"
)

const (
	maxRecentAIAuditEntries      = 50
	maxAutomaticAIAttributeBytes = 24 * 1024
	maxAutomaticAITextBytes      = 8 * 1024
)

type aiJob struct {
	event    model.Event
	findings []model.Finding
}

type AIAuditEntry struct {
	Timestamp        time.Time `json:"timestamp"`
	Operation        string    `json:"operation"`
	Status           string    `json:"status"`
	EventID          string    `json:"event_id,omitempty"`
	FindingIDs       []string  `json:"finding_ids,omitempty"`
	Model            string    `json:"model,omitempty"`
	DurationMS       int64     `json:"duration_ms,omitempty"`
	PromptTokens     int       `json:"prompt_tokens,omitempty"`
	CompletionTokens int       `json:"completion_tokens,omitempty"`
	TotalTokens      int       `json:"total_tokens,omitempty"`
	AnalysisEventID  string    `json:"analysis_event_id,omitempty"`
	Error            string    `json:"error,omitempty"`
}

type AIStatus struct {
	Enabled         bool           `json:"enabled"`
	AutoAnalyze     bool           `json:"auto_analyze"`
	Endpoint        string         `json:"endpoint,omitempty"`
	Model           string         `json:"model,omitempty"`
	MinimumSeverity model.Severity `json:"minimum_severity,omitempty"`
	QueueDepth      int            `json:"queue_depth"`
	QueueCapacity   int            `json:"queue_capacity"`
	Requests        uint64         `json:"requests"`
	Successes       uint64         `json:"successes"`
	Failures        uint64         `json:"failures"`
	Dropped         uint64         `json:"dropped"`
	LastStartedAt   *time.Time     `json:"last_started_at,omitempty"`
	LastSuccessAt   *time.Time     `json:"last_success_at,omitempty"`
	LastError       string         `json:"last_error,omitempty"`
	AuditLogFile    string         `json:"audit_log_file,omitempty"`
	Recent          []AIAuditEntry `json:"recent"`
}

func (r *Runtime) enqueueAI(event model.Event, findings []model.Finding) {
	if r.aiQueue == nil || len(findings) == 0 || event.Kind == "ai.analysis" {
		return
	}
	if severityRank(highestFindingSeverity(findings)) < severityRank(r.cfg.AI.MinimumSeverity) {
		return
	}
	job := aiJob{event: event, findings: append([]model.Finding(nil), findings...)}
	select {
	case r.aiQueue <- job:
		r.recordAIAudit(AIAuditEntry{
			Timestamp: time.Now().UTC(), Operation: "analysis", Status: "queued",
			EventID: event.ID, FindingIDs: findingIDs(findings), Model: r.cfg.AI.Model,
		})
	default:
		r.aiDropped.Add(1)
		entry := AIAuditEntry{
			Timestamp: time.Now().UTC(), Operation: "analysis", Status: "dropped_queue_full",
			EventID: event.ID, FindingIDs: findingIDs(findings), Model: r.cfg.AI.Model,
		}
		r.recordAIAudit(entry)
		r.logger.Printf("llm operation=analysis status=dropped_queue_full event_id=%s queue_depth=%d queue_capacity=%d", event.ID, len(r.aiQueue), cap(r.aiQueue))
	}
}

func (r *Runtime) runAI(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.aiQueue:
			if last := r.lastAIStartNano.Load(); last != 0 {
				wait := r.aiMinInterval - time.Since(time.Unix(0, last))
				if wait > 0 {
					timer := time.NewTimer(wait)
					select {
					case <-ctx.Done():
						timer.Stop()
						return
					case <-timer.C:
					}
				}
			}
			r.analyzeAIJob(ctx, job)
		}
	}
}

func (r *Runtime) analyzeAIJob(ctx context.Context, job aiJob) {
	started := time.Now().UTC()
	r.lastAIStartNano.Store(started.UnixNano())
	r.aiRequests.Add(1)
	ids := findingIDs(job.findings)
	r.recordAIAudit(AIAuditEntry{
		Timestamp: started, Operation: "analysis", Status: "started",
		EventID: job.event.ID, FindingIDs: ids, Model: r.cfg.AI.Model,
	})
	r.logger.Printf("llm operation=analysis status=started event_id=%s finding_count=%d model=%s", job.event.ID, len(job.findings), r.cfg.AI.Model)

	analysis, err := r.aiClient.Analyze(ctx, ai.IncidentBundle{
		Objective: "วิเคราะห์เหตุการณ์ EDR/NGAV นี้ อธิบายสิ่งที่พบ ระดับความเสี่ยง หลักฐาน ข้อมูลที่ยังขาด และขั้นตอนตรวจสอบแบบอ่านอย่างเดียว ตอบภาษาไทยแบบกระชับ",
		Events:    []model.Event{compactAIEvent(job.event)},
		Findings:  job.findings,
	})
	duration := time.Since(started)
	if err != nil {
		r.aiFailures.Add(1)
		r.errorCount.Add(1)
		safeError := redact.String(err.Error())
		if len(safeError) > 300 {
			safeError = safeError[:300] + "…"
		}
		r.aiAuditMu.Lock()
		r.aiLastError = safeError
		r.aiAuditMu.Unlock()
		r.recordAIAudit(AIAuditEntry{
			Timestamp: time.Now().UTC(), Operation: "analysis", Status: "failed",
			EventID: job.event.ID, FindingIDs: ids, Model: r.cfg.AI.Model,
			DurationMS: duration.Milliseconds(), Error: safeError,
		})
		r.logger.Printf("llm operation=analysis status=failed event_id=%s duration_ms=%d error=%s", job.event.ID, duration.Milliseconds(), safeError)
		return
	}

	analysisEvent, err := r.recordAIAnalysis(job, analysis, duration)
	if err != nil {
		r.aiFailures.Add(1)
		r.errorCount.Add(1)
		safeError := redact.String(err.Error())
		r.recordAIAudit(AIAuditEntry{
			Timestamp: time.Now().UTC(), Operation: "analysis", Status: "record_failed",
			EventID: job.event.ID, FindingIDs: ids, Model: analysis.Model,
			DurationMS: duration.Milliseconds(), Error: safeError,
		})
		r.logger.Printf("llm operation=analysis status=record_failed event_id=%s duration_ms=%d error=%s", job.event.ID, duration.Milliseconds(), safeError)
		return
	}

	r.aiSuccesses.Add(1)
	r.lastAISuccessNano.Store(time.Now().UTC().UnixNano())
	r.aiAuditMu.Lock()
	r.aiLastError = ""
	r.aiAuditMu.Unlock()
	r.recordAIAudit(AIAuditEntry{
		Timestamp: time.Now().UTC(), Operation: "analysis", Status: "succeeded",
		EventID: job.event.ID, FindingIDs: ids, Model: analysis.Model,
		DurationMS: duration.Milliseconds(), PromptTokens: analysis.PromptTokens,
		CompletionTokens: analysis.CompletionTokens, TotalTokens: analysis.TotalTokens,
		AnalysisEventID: analysisEvent.ID,
	})
	r.logger.Printf("llm operation=analysis status=succeeded event_id=%s analysis_event_id=%s model=%s duration_ms=%d prompt_tokens=%d completion_tokens=%d total_tokens=%d", job.event.ID, analysisEvent.ID, analysis.Model, duration.Milliseconds(), analysis.PromptTokens, analysis.CompletionTokens, analysis.TotalTokens)
}

func (r *Runtime) recordAIAnalysis(job aiJob, analysis ai.Analysis, duration time.Duration) (model.Event, error) {
	ids := findingIDs(job.findings)
	event := model.Event{
		Kind:     "ai.analysis",
		Severity: highestFindingSeverity(job.findings),
		Trust:    model.TrustUntrustedTelemetry,
		Asset:    job.event.Asset,
		Message:  analysis.Content,
		Attributes: map[string]interface{}{
			"source_event_id":   job.event.ID,
			"finding_ids":       ids,
			"provider_endpoint": analysis.ProviderEndpoint,
			"model":             analysis.Model,
			"read_only":         analysis.ReadOnly,
			"tools_exposed":     analysis.ToolsExposed,
			"request_id":        analysis.RequestID,
			"finish_reason":     analysis.FinishReason,
			"duration_ms":       duration.Milliseconds(),
			"prompt_tokens":     analysis.PromptTokens,
			"completion_tokens": analysis.CompletionTokens,
			"total_tokens":      analysis.TotalTokens,
		},
		Provenance: model.Provenance{Source: "ai-investigator", Collector: "llm/openai-compatible"},
	}
	event.Prepare()
	event.AgentID = r.cfg.AgentID
	event.TenantID = r.cfg.TenantID
	if event.Asset.Hostname == "" {
		event.Asset.Hostname = r.hostname
	}
	redact.Event(&event)
	if _, err := r.journal.Append("event", event); err != nil {
		return model.Event{}, fmt.Errorf("append AI analysis evidence: %w", err)
	}
	r.eventCount.Add(1)
	if r.transportOutbox != nil {
		if err := r.transportOutbox.Enqueue(event); err != nil {
			return model.Event{}, fmt.Errorf("queue AI analysis for Control Plane: %w", err)
		}
	}
	finding := model.NewFinding(
		event,
		"NTS-AI-ENRICH-001",
		"AI investigation enrichment (read-only)",
		analysis.Content,
		"ai.analysis",
		event.Severity,
		50,
	)
	finding.EvidenceEventIDs = []string{job.event.ID, event.ID}
	finding.Attributes = map[string]interface{}{
		"generated_by_ai":   true,
		"read_only":         analysis.ReadOnly,
		"tools_exposed":     analysis.ToolsExposed,
		"model":             analysis.Model,
		"duration_ms":       duration.Milliseconds(),
		"prompt_tokens":     analysis.PromptTokens,
		"completion_tokens": analysis.CompletionTokens,
		"total_tokens":      analysis.TotalTokens,
	}
	if _, err := r.journal.Append("finding", finding); err != nil {
		return model.Event{}, fmt.Errorf("append AI analysis finding: %w", err)
	}
	r.findingCount.Add(1)
	if r.central != nil {
		r.central.Enqueue(event, []model.Finding{finding})
	}
	return event, nil
}

func (r *Runtime) recordAIAudit(entry AIAuditEntry) {
	entry.Error = redact.String(entry.Error)
	r.aiAuditMu.Lock()
	r.aiRecent = append(r.aiRecent, entry)
	if len(r.aiRecent) > maxRecentAIAuditEntries {
		r.aiRecent = append([]AIAuditEntry(nil), r.aiRecent[len(r.aiRecent)-maxRecentAIAuditEntries:]...)
	}
	r.aiAuditMu.Unlock()

	encoded, err := json.Marshal(entry)
	if err != nil || strings.TrimSpace(r.cfg.AI.AuditLogFile) == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.cfg.AI.AuditLogFile), 0o700); err != nil {
		return
	}
	file, err := os.OpenFile(r.cfg.AI.AuditLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = file.Write(append(encoded, '\n'))
	_ = file.Close()
	_ = os.Chmod(r.cfg.AI.AuditLogFile, 0o600)
	_, _ = r.journal.Append("ai.operation", entry)
}

func (r *Runtime) AIStatus() AIStatus {
	status := AIStatus{
		Enabled: r.aiClient != nil, AutoAnalyze: r.aiQueue != nil,
		Endpoint: r.cfg.AI.Endpoint, Model: r.cfg.AI.Model,
		MinimumSeverity: r.cfg.AI.MinimumSeverity,
		Requests:        r.aiRequests.Load(), Successes: r.aiSuccesses.Load(),
		Failures: r.aiFailures.Load(), Dropped: r.aiDropped.Load(),
		AuditLogFile: r.cfg.AI.AuditLogFile,
	}
	if r.aiQueue != nil {
		status.QueueDepth = len(r.aiQueue)
		status.QueueCapacity = cap(r.aiQueue)
	}
	if value := r.lastAIStartNano.Load(); value != 0 {
		at := time.Unix(0, value).UTC()
		status.LastStartedAt = &at
	}
	if value := r.lastAISuccessNano.Load(); value != 0 {
		at := time.Unix(0, value).UTC()
		status.LastSuccessAt = &at
	}
	r.aiAuditMu.RLock()
	status.LastError = r.aiLastError
	status.Recent = append([]AIAuditEntry(nil), r.aiRecent...)
	r.aiAuditMu.RUnlock()
	return status
}

func findingIDs(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	return ids
}

func highestFindingSeverity(findings []model.Finding) model.Severity {
	highest := model.SeverityInfo
	for _, finding := range findings {
		if severityRank(finding.Severity) > severityRank(highest) {
			highest = finding.Severity
		}
	}
	return highest
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	default:
		return 0
	}
}

func compactAIEvent(event model.Event) model.Event {
	event.Message = truncateAIText(event.Message)
	event.Process.CommandLine = truncateAIText(event.Process.CommandLine)
	event.HTTP.Query = truncateAIText(event.HTTP.Query)
	event.HTTP.UserAgent = truncateAIText(event.HTTP.UserAgent)

	if encoded, err := json.Marshal(event.Attributes); err == nil && len(encoded) > maxAutomaticAIAttributeBytes {
		keys := make([]string, 0, len(event.Attributes))
		for key := range event.Attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		event.Attributes = map[string]interface{}{
			"automatic_ai_compaction":  true,
			"original_attribute_bytes": len(encoded),
			"original_attribute_keys":  keys,
			"note":                     "Large attributes were omitted from automatic LLM analysis; the original event remains in the evidence journal.",
		}
	}
	return event
}

func truncateAIText(value string) string {
	if len(value) <= maxAutomaticAITextBytes {
		return value
	}
	return value[:maxAutomaticAITextBytes] + "…[truncated for automatic AI analysis]"
}
