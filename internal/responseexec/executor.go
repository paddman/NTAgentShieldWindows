package responseexec

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
	"github.com/paddman/NTAgentShieldWindows/internal/tools"
)

type ExecutorOptions struct {
	DataDir         string
	AgentID         string
	TenantID        string
	PolicyFile      string
	AllowedPaths    []string
	ControlEndpoint string
	IdentityKeyFile string
	TrustRootFile   string
}

// LocalExecutor is the only component allowed to turn a verified signed lease
// into a typed response call. It belongs in ntagentshield-response on Linux.
type LocalExecutor struct {
	options ExecutorOptions
	ledger  *Ledger
}

func NewLocalExecutor(options ExecutorOptions) (*LocalExecutor, error) {
	if options.TrustRootFile == "" {
		options.TrustRootFile = filepath.Join(options.DataDir, "response-signing.pub")
	}
	ledger, err := OpenLedger(filepath.Join(options.DataDir, "response-ledger.json"), options.IdentityKeyFile)
	if err != nil {
		return nil, err
	}
	return &LocalExecutor{options: options, ledger: ledger}, nil
}

func (e *LocalExecutor) Execute(ctx context.Context, bundle SignedLease, now time.Time) ([]byte, Lease, error) {
	lease, err := VerifyLease(bundle, e.options.TrustRootFile, e.options.TenantID, e.options.AgentID, now)
	if err != nil {
		return nil, Lease{}, err
	}
	request, digest, err := lease.ActionRequest()
	if err != nil {
		return nil, lease, err
	}
	stored, replay, beginErr := e.ledger.Begin(lease.ActionID, digest)
	if beginErr == nil && replay {
		return stored, lease, nil
	}
	if errors.Is(beginErr, ErrIndeterminate) {
		result := resultJSON(lease, "failed", "action state is indeterminate after restart; duplicate execution refused", ErrIndeterminate, nil)
		if err := e.ledger.Complete(lease.ActionID, digest, result); err != nil {
			return nil, lease, err
		}
		return result, lease, nil
	}
	if beginErr != nil {
		return nil, lease, beginErr
	}
	result := e.execute(ctx, lease, request)
	if err := e.ledger.Complete(lease.ActionID, digest, result); err != nil {
		return nil, lease, err
	}
	return result, lease, nil
}

func (e *LocalExecutor) execute(ctx context.Context, lease Lease, request model.ActionRequest) []byte {
	registry, err := tools.NewResponseRegistry(e.options.PolicyFile, tools.ContainmentOptions{
		DataDir:         e.options.DataDir,
		IdentityKeyFile: e.options.IdentityKeyFile,
		ControlEndpoint: e.options.ControlEndpoint,
		AllowedPaths:    e.options.AllowedPaths,
	})
	if err != nil {
		return resultJSON(lease, "failed", "unable to load active local policy/tool registry", err, nil)
	}
	var declaredRisk model.ActionRisk
	found := false
	for _, spec := range registry.Specs() {
		if spec.Name == lease.Tool {
			declaredRisk = spec.Risk
			found = true
			break
		}
	}
	if !found {
		return resultJSON(lease, "rejected", "response tool is not registered on this Agent", nil, nil)
	}
	if declaredRisk != lease.Risk {
		return resultJSON(lease, "rejected", "signed response risk does not match local tool risk", nil, nil)
	}
	result, decision, execErr := registry.Execute(ctx, request)
	if !decision.Allowed {
		return resultJSON(lease, "rejected", decision.Reason, nil, nil)
	}
	if execErr != nil {
		return resultJSON(lease, "failed", decision.Reason, execErr, nil)
	}
	data := map[string]interface{}{}
	if result.Data != nil {
		if mapped, ok := result.Data.(map[string]interface{}); ok {
			data = mapped
		} else {
			data["value"] = result.Data
		}
	}
	return resultJSON(lease, "succeeded", decision.Reason, nil, data)
}
