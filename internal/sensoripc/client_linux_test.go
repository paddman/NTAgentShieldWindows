//go:build linux

package sensoripc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paddman/NTAgentShieldWindows/internal/model"
)

func TestClientAcknowledgesOnlyAfterSinkSuccess(t *testing.T) {
	broker, err := NewBroker(128, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Add(model.Event{ID: "evt-journal-bound", Kind: "process.exec"}); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "sensor.sock")
	server, err := NewServer(ServerOptions{Broker: broker, SocketPath: socketPath, AllowedUIDs: []uint32{uint32(os.Getuid())}, MaxMessageSize: 64 * 1024, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(serverContext) }()
	for deadline := time.Now().Add(time.Second); ; {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sensor IPC server did not start")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := NewClient(socketPath, 64*1024, 8, time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	sinkError := errors.New("journal unavailable")
	if err := client.Run(t.Context(), func(model.Event) error { return sinkError }, nil); !errors.Is(err, sinkError) {
		t.Fatalf("sink failure was not returned: %v", err)
	}
	if broker.pendingID == "" || len(broker.pending) != 1 {
		t.Fatal("failed sink advanced the sensor batch")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	seen := 0
	err = client.Run(ctx, func(event model.Event) error {
		seen++
		if event.ID != "evt-journal-bound" {
			t.Fatalf("unexpected replay event: %#v", event)
		}
		return nil
	}, func(health Health) {
		if seen == 1 && health.QueueDepth == 0 {
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 1 || broker.pendingID != "" || len(broker.pending) != 0 {
		t.Fatalf("successful sink did not acknowledge exactly once: seen=%d pending=%q", seen, broker.pendingID)
	}
	stopServer()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("sensor IPC server did not stop")
	}
}
