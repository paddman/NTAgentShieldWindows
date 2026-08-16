//go:build linux

package helperipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type echoPayload struct {
	Value string `json:"value"`
}

func TestServerValidatesPeerAndTypedRequest(t *testing.T) {
	var mu sync.Mutex
	var audits []AuditRecord
	server, client, cancel := startTestServer(t, ServerOptions{
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		Methods: map[string]Handler{
			"test.echo": func(_ context.Context, peer Peer, raw json.RawMessage) (interface{}, error) {
				if int(peer.UID) != os.Getuid() {
					t.Fatal("handler received unverified peer")
				}
				var payload echoPayload
				if err := decodeStrict(raw, &payload); err != nil {
					return nil, err
				}
				return payload, nil
			},
		},
		Audit: func(record AuditRecord) {
			mu.Lock()
			defer mu.Unlock()
			audits = append(audits, record)
		},
	})
	defer cancel()
	_ = server
	var result echoPayload
	if err := client.Call(context.Background(), "test.echo", echoPayload{Value: "evidence"}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Value != "evidence" {
		t.Fatalf("unexpected result %#v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(audits) != 1 || !audits[0].Allowed || audits[0].Result != "succeeded" || audits[0].Peer.PID == 0 {
		t.Fatalf("missing peer audit: %#v", audits)
	}
}

func TestServerRejectsUnauthorizedPeer(t *testing.T) {
	_, client, cancel := startTestServer(t, ServerOptions{
		AllowedUIDs: []uint32{uint32(os.Getuid() + 1)},
		Methods: map[string]Handler{
			"test.echo": func(context.Context, Peer, json.RawMessage) (interface{}, error) { return echoPayload{}, nil },
		},
	})
	defer cancel()
	if err := client.Call(context.Background(), "test.echo", echoPayload{}, &echoPayload{}); err == nil {
		t.Fatal("unauthorized peer was accepted")
	}
}

func TestServerRejectsReplayAndOversizeFrames(t *testing.T) {
	server, _, cancel := startTestServer(t, ServerOptions{
		AllowedUIDs:    []uint32{uint32(os.Getuid())},
		MaxMessageSize: 2048,
		Methods: map[string]Handler{
			"test.echo": func(context.Context, Peer, json.RawMessage) (interface{}, error) {
				return echoPayload{Value: "ok"}, nil
			},
		},
	})
	defer cancel()
	request := Request{Version: ProtocolVersion, RequestID: "req_fixed", Method: "test.echo", IssuedAt: time.Now().UTC(), Payload: json.RawMessage(`{"value":"one"}`)}
	first := rawRequest(t, server.options.SocketPath, request, 2048)
	if !first.OK {
		t.Fatalf("first request rejected: %#v", first)
	}
	second := rawRequest(t, server.options.SocketPath, request, 2048)
	if second.OK || !strings.Contains(second.Error, "replay") {
		t.Fatalf("replay not rejected: %#v", second)
	}

	connection, err := net.Dial("unix", server.options.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := writeFrame(connection, make([]byte, 2049), 4096); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("oversize frame received a successful response")
	}
}

func TestServerEnforcesHandlerTimeout(t *testing.T) {
	_, client, cancel := startTestServer(t, ServerOptions{
		AllowedUIDs: []uint32{uint32(os.Getuid())},
		Timeout:     100 * time.Millisecond,
		Methods: map[string]Handler{
			"test.wait": func(ctx context.Context, _ Peer, _ json.RawMessage) (interface{}, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
	})
	defer cancel()
	if err := client.Call(context.Background(), "test.wait", struct{}{}, nil); err == nil {
		t.Fatal("timed-out handler succeeded")
	}
}

func startTestServer(t *testing.T, options ServerOptions) (*Server, *Client, context.CancelFunc) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	options.SocketPath = filepath.Join(directory, "helper.sock")
	if options.Timeout == 0 {
		options.Timeout = time.Second
	}
	server, err := NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	for deadline := time.Now().Add(time.Second); ; {
		if _, err := os.Stat(options.SocketPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("helper socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	client, err := NewClient(ClientOptions{SocketPath: options.SocketPath, MaxMessageSize: options.MaxMessageSize, Timeout: options.Timeout})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return server, client, cancel
}

func rawRequest(t *testing.T, socketPath string, request Request, maximum int) Response {
	t.Helper()
	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(connection, encoded, maximum); err != nil {
		t.Fatal(err)
	}
	responseBytes, err := readFrame(connection, maximum)
	if err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := decodeStrict(responseBytes, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
