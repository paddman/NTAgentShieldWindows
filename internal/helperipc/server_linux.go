//go:build linux

package helperipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Server struct {
	options ServerOptions
	mu      sync.Mutex
	seen    map[string]time.Time
	slots   chan struct{}
}

func NewServer(options ServerOptions) (*Server, error) {
	if options.SocketPath == "" || !filepath.IsAbs(options.SocketPath) {
		return nil, errors.New("helper socket path must be absolute")
	}
	if options.SocketMode == 0 {
		options.SocketMode = 0o660
	}
	if options.SocketMode&^0o660 != 0 {
		return nil, errors.New("helper socket mode cannot grant world or execute permissions")
	}
	if options.MaxMessageSize == 0 {
		options.MaxMessageSize = DefaultMaxMessageSize
	}
	if options.MaxMessageSize < 1024 || options.MaxMessageSize > 1024*1024 {
		return nil, errors.New("helper maximum message size must be between 1024 and 1048576 bytes")
	}
	if options.Timeout == 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Timeout < 100*time.Millisecond || options.Timeout > time.Minute {
		return nil, errors.New("helper timeout must be between 100ms and 1m")
	}
	if options.ReplayTTL == 0 {
		options.ReplayTTL = 5 * time.Minute
	}
	if options.ReplayTTL < time.Second || options.ReplayTTL > time.Hour {
		return nil, errors.New("helper replay TTL must be between 1s and 1h")
	}
	if options.MaxReplayIDs == 0 {
		options.MaxReplayIDs = 4096
	}
	if options.MaxReplayIDs < 16 || options.MaxReplayIDs > 65536 {
		return nil, errors.New("helper replay ID bound must be between 16 and 65536")
	}
	if options.MaxConnections == 0 {
		options.MaxConnections = 64
	}
	if options.MaxConnections < 1 || options.MaxConnections > 1024 {
		return nil, errors.New("helper connection bound must be between 1 and 1024")
	}
	if len(options.AllowedUIDs) == 0 && len(options.AllowedGIDs) == 0 {
		return nil, errors.New("helper requires an allowed peer UID or GID")
	}
	if len(options.Methods) == 0 {
		return nil, errors.New("helper requires at least one typed method")
	}
	for method, handler := range options.Methods {
		if !validMethod(method) || handler == nil {
			return nil, fmt.Errorf("invalid helper method %q", method)
		}
	}
	return &Server{options: options, seen: make(map[string]time.Time), slots: make(chan struct{}, options.MaxConnections)}, nil
}

func (s *Server) Run(ctx context.Context) error {
	parent := filepath.Dir(s.options.SocketPath)
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("stat helper socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o002 != 0 {
		return errors.New("helper socket directory must exist and not be world-writable")
	}
	if existing, err := os.Lstat(s.options.SocketPath); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return errors.New("helper socket path exists and is not a socket")
		}
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("existing helper socket is not owned by this service identity")
		}
		if active, dialErr := net.DialTimeout("unix", s.options.SocketPath, 100*time.Millisecond); dialErr == nil {
			_ = active.Close()
			return errors.New("helper socket is already active")
		}
		if err := os.Remove(s.options.SocketPath); err != nil {
			return fmt.Errorf("remove stale helper socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.options.SocketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen helper socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(s.options.SocketPath)
	if err := os.Chmod(s.options.SocketPath, os.FileMode(s.options.SocketMode)); err != nil {
		return fmt.Errorf("secure helper socket mode: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept helper peer: %w", err)
		}
		select {
		case s.slots <- struct{}{}:
			go func() {
				defer func() { <-s.slots }()
				s.serve(ctx, connection)
			}()
		default:
			s.audit(AuditRecord{Timestamp: time.Now().UTC(), Allowed: false, Result: "connection_limit"})
			_ = connection.Close()
		}
	}
}

func (s *Server) serve(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	peer, err := socketPeer(connection)
	if err != nil || !s.allowed(peer) {
		s.audit(AuditRecord{Timestamp: time.Now().UTC(), Peer: peer, Allowed: false, Result: "peer_rejected"})
		return
	}
	deadline := time.Now().Add(s.options.Timeout)
	_ = connection.SetDeadline(deadline)
	content, err := readFrame(connection, s.options.MaxMessageSize)
	if err != nil {
		s.audit(AuditRecord{Timestamp: time.Now().UTC(), Peer: peer, Allowed: true, Result: "frame_rejected"})
		return
	}
	var request Request
	if err := decodeStrict(content, &request); err != nil {
		s.writeError(connection, request.RequestID, "invalid request schema")
		s.audit(AuditRecord{Timestamp: time.Now().UTC(), RequestID: request.RequestID, Peer: peer, Allowed: true, Result: "schema_rejected"})
		return
	}
	record := AuditRecord{Timestamp: time.Now().UTC(), RequestID: request.RequestID, Method: request.Method, Peer: peer, Allowed: true}
	if request.Version != ProtocolVersion || !validRequestID(request.RequestID) || !validMethod(request.Method) {
		s.writeError(connection, request.RequestID, "invalid request binding")
		record.Result = "binding_rejected"
		s.audit(record)
		return
	}
	if request.IssuedAt.IsZero() || delta(time.Now().UTC(), request.IssuedAt.UTC()) > s.options.ReplayTTL {
		s.writeError(connection, request.RequestID, "request timestamp outside replay window")
		record.Result = "timestamp_rejected"
		s.audit(record)
		return
	}
	if !s.acceptRequestID(request.RequestID, time.Now().UTC()) {
		s.writeError(connection, request.RequestID, ErrReplay.Error())
		record.Result = "replay_rejected"
		s.audit(record)
		return
	}
	handler, exists := s.options.Methods[request.Method]
	if !exists {
		s.writeError(connection, request.RequestID, "unsupported typed method")
		record.Result = "method_rejected"
		s.audit(record)
		return
	}
	requestContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	result, err := handler(requestContext, peer, request.Payload)
	if err != nil {
		s.writeError(connection, request.RequestID, boundedError(err))
		record.Result = "handler_rejected"
		s.audit(record)
		return
	}
	payload, err := json.Marshal(result)
	if err != nil {
		s.writeError(connection, request.RequestID, "result encoding failed")
		record.Result = "encoding_failed"
		s.audit(record)
		return
	}
	response, _ := json.Marshal(Response{Version: ProtocolVersion, RequestID: request.RequestID, OK: true, Payload: payload})
	if err := writeFrame(connection, response, s.options.MaxMessageSize); err != nil {
		record.Result = "write_failed"
	} else {
		record.Result = "succeeded"
	}
	s.audit(record)
}

func (s *Server) allowed(peer Peer) bool {
	for _, uid := range s.options.AllowedUIDs {
		if peer.UID == uid {
			return true
		}
	}
	for _, gid := range s.options.AllowedGIDs {
		if peer.GID == gid {
			return true
		}
	}
	return false
}

func (s *Server) acceptRequestID(requestID string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, seenAt := range s.seen {
		if now.Sub(seenAt) > s.options.ReplayTTL {
			delete(s.seen, key)
		}
	}
	if _, exists := s.seen[requestID]; exists {
		return false
	}
	if len(s.seen) >= s.options.MaxReplayIDs {
		oldestKey := ""
		for key, seenAt := range s.seen {
			if oldestKey == "" || seenAt.Before(s.seen[oldestKey]) || (seenAt.Equal(s.seen[oldestKey]) && key < oldestKey) {
				oldestKey = key
			}
		}
		delete(s.seen, oldestKey)
	}
	s.seen[requestID] = now
	return true
}

func (s *Server) writeError(connection net.Conn, requestID, message string) {
	if !validRequestID(requestID) {
		requestID = "invalid"
	}
	response, _ := json.Marshal(Response{Version: ProtocolVersion, RequestID: requestID, OK: false, Error: message})
	_ = writeFrame(connection, response, s.options.MaxMessageSize)
}

func (s *Server) audit(record AuditRecord) {
	if s.options.Audit != nil {
		s.options.Audit(record)
	}
}

func socketPeer(connection *net.UnixConn) (Peer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if controlErr != nil || credential == nil {
		return Peer{}, controlErr
	}
	return Peer{PID: credential.Pid, UID: credential.Uid, GID: credential.Gid}, nil
}

func delta(left, right time.Time) time.Duration {
	value := left.Sub(right)
	if value < 0 {
		return -value
	}
	return value
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 512 {
		return message[:512]
	}
	return message
}
