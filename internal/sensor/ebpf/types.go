// Package ebpf provides a Linux-only, CO-RE telemetry sensor. It observes
// fixed kernel tracepoints and has no response, command, or policy interface.
package ebpf

import (
	"errors"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

var ErrUnsupported = errors.New("eBPF sensor is unavailable on this host")

const (
	defaultRingBufferBytes = 16 * 1024 * 1024
	defaultMaxEventsPerSec = 20000
)

type Options struct {
	RingBufferBytes int
	MaxEventsPerSec int
}

type Health struct {
	Enabled         bool      `json:"enabled"`
	LoadedPrograms  int       `json:"loaded_programs"`
	AttachedHooks   int       `json:"attached_hooks"`
	RingBufferLoss  uint64    `json:"ring_buffer_loss"`
	ParseErrors     uint64    `json:"parse_errors"`
	EventsPerSecond uint64    `json:"events_per_second"`
	ThrottledEvents uint64    `json:"throttled_events"`
	LastEventAt     time.Time `json:"last_event_at,omitempty"`
	FallbackReason  string    `json:"fallback_reason,omitempty"`
}

type EventSink func(model.Event) error
