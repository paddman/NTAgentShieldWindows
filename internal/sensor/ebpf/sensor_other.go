//go:build !linux

package ebpf

import (
	"context"

	"github.com/paddman/NTAgentShieldWindows/internal/processgraph"
)

// Sensor is an unsupported-platform placeholder. It deliberately provides no
// alternate execution mechanism and no non-Linux telemetry feature.
type Sensor struct{}

func New(_ *processgraph.Graph, _ Options) (*Sensor, error)  { return nil, ErrUnsupported }
func CheckSupport() error                                    { return ErrUnsupported }
func (s *Sensor) Start(_ context.Context, _ EventSink) error { return ErrUnsupported }
func (s *Sensor) Close() error                               { return nil }
func (s *Sensor) Health() Health                             { return Health{FallbackReason: ErrUnsupported.Error()} }
