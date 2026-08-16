# Changelog

## 0.2.9 - Automatic read-only LLM enrichment

- Added asynchronous severity-gated LLM analysis with bounded queueing and rate limiting.
- Added protected API-key-file loading and structured LLM operation audit logs without secret persistence.
- Added authenticated `/v1/ai` health and usage counters.
- Added compact `ai.analysis` events and `NTS-AI-ENRICH-001` findings for Shield Central.
- Added request ID, finish reason, latency, and token-usage accounting for OpenAI-compatible responses.
- Added bounded evidence compaction to prevent oversized inventory prompts while retaining original journal evidence.
- Added direct redaction for NTShield LLM token values found in monitored process command lines.

## 0.1.0 - Secure Agent Foundation

- Added cross-platform agent daemon and operator CLI.
- Added IIS, Nginx, MySQL, Syslog, JSONL, and raw log parsers.
- Added deterministic endpoint/web/database/AI-input detections.
- Added source-code security scanner.
- Added read-only OpenAI-compatible AI investigator with no tool exposure.
- Added tamper-evident evidence journal, redaction, policy gate, and typed read-only tools.
- Added Windows/Linux configuration templates, service packaging, CI, schemas, and security documentation.
