package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

var ErrUnsupportedPlatform = errors.New("native telemetry source is unsupported on this platform")

type Source interface {
	ID() string
	Kind() string
	Poll(context.Context) (Batch, []error)
}

type Batch struct {
	Events           []model.Event
	cursor           *cursorFile
	next             *cursorState
	afterAcknowledge func()
}

func (b Batch) Acknowledge() error {
	if b.cursor == nil || b.next == nil {
		return nil
	}
	if err := b.cursor.Commit(*b.next); err != nil {
		return err
	}
	if b.afterAcknowledge != nil {
		b.afterAcknowledge()
	}
	return nil
}

func deterministicEventID(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return "evt_" + hex.EncodeToString(hash.Sum(nil))
}
