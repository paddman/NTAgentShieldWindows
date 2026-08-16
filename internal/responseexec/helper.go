package responseexec

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/helperipc"
)

const responseExecuteMethod = "response.execute"

type HelperExecuteRequest struct {
	Lease SignedLease `json:"lease"`
}

type HelperExecuteResponse struct {
	ActionID string          `json:"action_id"`
	Result   json.RawMessage `json:"result"`
}

type HelperServerOptions struct {
	Executor       *LocalExecutor
	SocketPath     string
	SocketMode     uint32
	AllowedUIDs    []uint32
	AllowedGIDs    []uint32
	MaxMessageSize int
	Timeout        time.Duration
	Audit          func(helperipc.AuditRecord)
}

func NewHelperServer(options HelperServerOptions) (*helperipc.Server, error) {
	if options.Executor == nil {
		return nil, errors.New("response helper executor is required")
	}
	return helperipc.NewServer(helperipc.ServerOptions{
		SocketPath: options.SocketPath, SocketMode: options.SocketMode,
		AllowedUIDs: options.AllowedUIDs, AllowedGIDs: options.AllowedGIDs,
		MaxMessageSize: options.MaxMessageSize, Timeout: options.Timeout,
		Methods: map[string]helperipc.Handler{
			responseExecuteMethod: func(ctx context.Context, _ helperipc.Peer, raw json.RawMessage) (interface{}, error) {
				var request HelperExecuteRequest
				if err := decodeStrict(raw, &request); err != nil {
					return nil, err
				}
				result, lease, err := options.Executor.Execute(ctx, request.Lease, time.Now().UTC())
				if err != nil {
					return nil, err
				}
				return HelperExecuteResponse{ActionID: lease.ActionID, Result: result}, nil
			},
		},
		Audit: options.Audit,
	})
}

type BrokerRunner struct {
	client   *Client
	helper   *helperipc.Client
	interval time.Duration
}

type BrokerRunnerOptions struct {
	ClientOptions
	HelperSocketPath string
	HelperMaxMessage int
	HelperTimeout    time.Duration
	Interval         time.Duration
}

func NewBrokerRunner(options BrokerRunnerOptions) (*BrokerRunner, error) {
	client, err := NewClient(options.ClientOptions)
	if err != nil {
		return nil, err
	}
	helper, err := helperipc.NewClient(helperipc.ClientOptions{SocketPath: options.HelperSocketPath, MaxMessageSize: options.HelperMaxMessage, Timeout: options.HelperTimeout})
	if err != nil {
		return nil, err
	}
	if options.Interval <= 0 {
		options.Interval = 5 * time.Second
	}
	return &BrokerRunner{client: client, helper: helper, interval: options.Interval}, nil
}

func (r *BrokerRunner) Run(ctx context.Context, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if err := r.client.EnsureTrustRoot(ctx); err != nil {
		logger.Printf("response broker trust bootstrap unavailable: %v", err)
	}
	r.sync(ctx, logger)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sync(ctx, logger)
		}
	}
}

func (r *BrokerRunner) sync(ctx context.Context, logger *log.Logger) {
	if err := r.client.EnsureTrustRoot(ctx); err != nil {
		logger.Printf("response broker trust check rejected/error: %v", err)
		return
	}
	bundle, err := r.client.Fetch(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Printf("response broker fetch error: %v", err)
		}
		return
	}
	if bundle == nil {
		return
	}
	var response HelperExecuteResponse
	if err := r.helper.Call(ctx, responseExecuteMethod, HelperExecuteRequest{Lease: *bundle}, &response); err != nil {
		logger.Printf("privileged response helper rejected/error: %v", err)
		return
	}
	if response.ActionID == "" || !json.Valid(response.Result) {
		logger.Printf("privileged response helper returned an invalid bounded result")
		return
	}
	if err := r.client.PostResult(ctx, response.ActionID, response.Result); err != nil {
		logger.Printf("response result ACK failed action=%s; helper ledger prevents re-execution: %v", response.ActionID, err)
		return
	}
	logger.Printf("response action terminal action=%s", response.ActionID)
}
