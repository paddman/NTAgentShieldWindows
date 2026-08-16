package responseexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

type RunnerOptions struct {
	DataDir           string
	AgentID           string
	TenantID          string
	PolicyFile        string
	AllowedPaths      []string
	TransportEndpoint string
	CertFile          string
	KeyFile           string
	CAFile            string
	ServerName        string
	Timeout           time.Duration
	Interval          time.Duration
}

type Runner struct {
	options  RunnerOptions
	client   *Client
	executor *LocalExecutor
}

type ResultPayload struct {
	ActionID       string                 `json:"action_id"`
	TenantID       string                 `json:"tenant_id"`
	AgentID        string                 `json:"agent_id"`
	Tool           string                 `json:"tool"`
	Status         string                 `json:"status"`
	DecisionReason string                 `json:"decision_reason"`
	Error          *string                `json:"error"`
	ExecutedAt     time.Time              `json:"executed_at"`
	Data           map[string]interface{} `json:"data"`
}

func NewRunner(options RunnerOptions) (*Runner, error) {
	if options.Interval <= 0 {
		options.Interval = 5 * time.Second
	}
	trustRoot := filepath.Join(options.DataDir, "trust", "response-signing.pub")
	client, err := NewClient(ClientOptions{
		TransportEndpoint: options.TransportEndpoint,
		AgentID:           options.AgentID,
		TenantID:          options.TenantID,
		CertFile:          options.CertFile,
		KeyFile:           options.KeyFile,
		CAFile:            options.CAFile,
		ServerName:        options.ServerName,
		TrustRootFile:     trustRoot,
		Timeout:           options.Timeout,
	})
	if err != nil {
		return nil, err
	}
	executor, err := NewLocalExecutor(ExecutorOptions{
		DataDir: options.DataDir, AgentID: options.AgentID, TenantID: options.TenantID,
		PolicyFile: options.PolicyFile, AllowedPaths: options.AllowedPaths,
		ControlEndpoint: options.TransportEndpoint, IdentityKeyFile: options.KeyFile,
		TrustRootFile: trustRoot,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, client: client, executor: executor}, nil
}

func (r *Runner) Run(ctx context.Context, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if err := r.client.EnsureTrustRoot(ctx); err != nil {
		logger.Printf("response broker trust bootstrap unavailable: %v", err)
	}
	r.sync(ctx, logger)
	ticker := time.NewTicker(r.options.Interval)
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

func (r *Runner) sync(ctx context.Context, logger *log.Logger) {
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
	result, lease, err := r.executor.Execute(ctx, *bundle, time.Now().UTC())
	if err != nil {
		logger.Printf("response lease rejected/error: %v", err)
		return
	}
	if err := r.client.PostResult(ctx, lease.ActionID, result); err != nil {
		logger.Printf("response result ACK failed action=%s; durable result will be retried: %v", lease.ActionID, err)
		return
	}
	logger.Printf("response action terminal action=%s tool=%s", lease.ActionID, lease.Tool)
}

func resultJSON(lease Lease, status, reason string, err error, data map[string]interface{}) []byte {
	if data == nil {
		data = map[string]interface{}{}
	}
	var errorText *string
	if err != nil {
		text := err.Error()
		errorText = &text
	}
	payload := ResultPayload{
		ActionID:       lease.ActionID,
		TenantID:       lease.TenantID,
		AgentID:        lease.AgentID,
		Tool:           lease.Tool,
		Status:         status,
		DecisionReason: reason,
		Error:          errorText,
		ExecutedAt:     time.Now().UTC(),
		Data:           data,
	}
	encoded, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		return []byte(fmt.Sprintf(`{"action_id":%q,"tenant_id":%q,"agent_id":%q,"tool":%q,"status":"failed","decision_reason":"result encoding failed","error":%q,"executed_at":%q,"data":{}}`, lease.ActionID, lease.TenantID, lease.AgentID, lease.Tool, marshalErr.Error(), time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return encoded
}
