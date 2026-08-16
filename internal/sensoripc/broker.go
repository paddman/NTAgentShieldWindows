// Package sensoripc provides the fixed telemetry-only interface between the
// Linux eBPF helper and the unprivileged core Agent.
package sensoripc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/helperipc"
	"github.com/paddman/NTAgentShieldWindows/internal/model"
	ebpfsensor "github.com/paddman/NTAgentShieldWindows/internal/sensor/ebpf"
)

const pollMethod = "sensor.poll"

type PollRequest struct {
	AckBatchID string `json:"ack_batch_id,omitempty"`
	MaxEvents  int    `json:"max_events"`
}

type Health struct {
	Sensor       ebpfsensor.Health `json:"sensor"`
	QueueDepth   int               `json:"queue_depth"`
	QueueDropped uint64            `json:"queue_dropped"`
}

type PollResponse struct {
	BatchID string        `json:"batch_id,omitempty"`
	Events  []model.Event `json:"events"`
	Health  Health        `json:"health"`
}

type Broker struct {
	mu        sync.Mutex
	maximum   int
	queue     []model.Event
	pending   []model.Event
	pendingID string
	lastAckID string
	dropped   uint64
	sequence  uint64
	health    func() ebpfsensor.Health
}

func NewBroker(maximum int, health func() ebpfsensor.Health) (*Broker, error) {
	if maximum < 128 || maximum > 65536 {
		return nil, errors.New("sensor IPC queue bound must be between 128 and 65536 events")
	}
	if health == nil {
		health = func() ebpfsensor.Health { return ebpfsensor.Health{} }
	}
	return &Broker{maximum: maximum, queue: make([]model.Event, 0, maximum), health: health}, nil
}

func (b *Broker) Add(event model.Event) error {
	event.Trust = model.TrustUntrustedTelemetry
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.queue)+len(b.pending) >= b.maximum {
		if len(b.queue) == 0 {
			b.dropped++
			return errors.New("sensor IPC queue is full")
		}
		b.queue = b.queue[1:]
		b.dropped++
	}
	b.queue = append(b.queue, event)
	return nil
}

func (b *Broker) Poll(request PollRequest) (PollResponse, error) {
	if request.MaxEvents < 1 || request.MaxEvents > 256 {
		return PollResponse{}, errors.New("sensor poll max_events must be between 1 and 256")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if request.AckBatchID != "" {
		if request.AckBatchID == b.lastAckID {
			// The prior acknowledgement response may have been lost. Returning
			// the current pending batch makes ACK retry idempotent.
		} else if b.pendingID == "" || request.AckBatchID != b.pendingID {
			return PollResponse{}, errors.New("sensor batch acknowledgement mismatch")
		} else {
			b.lastAckID = b.pendingID
			b.pending, b.pendingID = nil, ""
		}
	}
	if b.pendingID == "" && len(b.queue) > 0 {
		count := min(request.MaxEvents, len(b.queue))
		b.pending = append([]model.Event(nil), b.queue[:count]...)
		b.queue = b.queue[count:]
		b.sequence++
		b.pendingID = batchID(b.sequence, b.pending)
	}
	return PollResponse{
		BatchID: b.pendingID,
		Events:  append([]model.Event(nil), b.pending...),
		Health:  Health{Sensor: b.health(), QueueDepth: len(b.queue) + len(b.pending), QueueDropped: b.dropped},
	}, nil
}

type ServerOptions struct {
	Broker         *Broker
	SocketPath     string
	SocketMode     uint32
	AllowedUIDs    []uint32
	AllowedGIDs    []uint32
	MaxMessageSize int
	Timeout        time.Duration
	Audit          func(helperipc.AuditRecord)
}

func NewServer(options ServerOptions) (*helperipc.Server, error) {
	if options.Broker == nil {
		return nil, errors.New("sensor IPC broker is required")
	}
	return helperipc.NewServer(helperipc.ServerOptions{
		SocketPath: options.SocketPath, SocketMode: options.SocketMode,
		AllowedUIDs: options.AllowedUIDs, AllowedGIDs: options.AllowedGIDs,
		MaxMessageSize: options.MaxMessageSize, Timeout: options.Timeout,
		Methods: map[string]helperipc.Handler{
			pollMethod: func(_ context.Context, _ helperipc.Peer, raw json.RawMessage) (interface{}, error) {
				var request PollRequest
				if err := strictJSON(raw, &request); err != nil {
					return nil, err
				}
				return options.Broker.Poll(request)
			},
		},
		Audit: options.Audit,
	})
}

type Client struct {
	ipc       *helperipc.Client
	maxEvents int
	interval  time.Duration
}

func NewClient(socketPath string, maxMessage, maxEvents int, timeout, interval time.Duration) (*Client, error) {
	if maxEvents < 1 || maxEvents > 256 {
		return nil, errors.New("sensor client batch size must be between 1 and 256")
	}
	if interval < 10*time.Millisecond || interval > time.Minute {
		return nil, errors.New("sensor client poll interval must be between 10ms and 1m")
	}
	client, err := helperipc.NewClient(helperipc.ClientOptions{SocketPath: socketPath, MaxMessageSize: maxMessage, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	return &Client{ipc: client, maxEvents: maxEvents, interval: interval}, nil
}

func (c *Client) Run(ctx context.Context, sink func(model.Event) error, health func(Health)) error {
	if sink == nil {
		return errors.New("sensor IPC event sink is required")
	}
	ack := ""
	for {
		if ctx.Err() != nil {
			return nil
		}
		var response PollResponse
		err := c.ipc.Call(ctx, pollMethod, PollRequest{AckBatchID: ack, MaxEvents: c.maxEvents}, &response)
		if err != nil {
			return err
		}
		ack = ""
		if health != nil {
			health(response.Health)
		}
		for _, event := range response.Events {
			if err := sink(event); err != nil {
				return err
			}
		}
		if response.BatchID != "" {
			ack = response.BatchID
		}
		if len(response.Events) == 0 {
			timer := time.NewTimer(c.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
	}
}

func batchID(sequence uint64, events []model.Event) string {
	parts := make([]string, 0, len(events)+1)
	parts = append(parts, strconv.FormatUint(sequence, 10))
	for _, event := range events {
		parts = append(parts, event.ID)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sensor_" + hex.EncodeToString(digest[:16])
}

func strictJSON(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}
