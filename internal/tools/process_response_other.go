//go:build !linux && !windows

package tools

import (
	"context"
	"errors"
)

var errProcessResponseUnsupported = errors.New("verified process response is implemented only on Linux")

func newProcessResponseBackend() processResponseBackend { return unsupportedProcessResponseBackend{} }

type unsupportedProcessResponseBackend struct{}

func (unsupportedProcessResponseBackend) Target(int) (processResponseTarget, error) {
	return processResponseTarget{}, errProcessResponseUnsupported
}
func (unsupportedProcessResponseBackend) Snapshot(int) ([]processResponseTarget, error) {
	return nil, errProcessResponseUnsupported
}
func (unsupportedProcessResponseBackend) Terminate(int) error { return errProcessResponseUnsupported }
func (unsupportedProcessResponseBackend) WaitExited(context.Context, processResponseTarget) error {
	return errProcessResponseUnsupported
}
