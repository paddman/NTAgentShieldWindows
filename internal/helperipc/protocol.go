// Package helperipc implements the bounded local protocol between the
// unprivileged Linux Agent and its narrowly privileged helpers.
package helperipc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ProtocolVersion       = "ntshield-helper/v1"
	DefaultMaxMessageSize = 64 * 1024
	DefaultTimeout        = 5 * time.Second
	maxRequestIDLength    = 96
)

var (
	ErrReplay       = errors.New("helper request replay rejected")
	ErrUnauthorized = errors.New("helper peer is not authorized")
	ErrUnsupported  = errors.New("helper IPC is unsupported on this platform")
)

type Request struct {
	Version   string          `json:"version"`
	RequestID string          `json:"request_id"`
	Method    string          `json:"method"`
	IssuedAt  time.Time       `json:"issued_at"`
	Payload   json.RawMessage `json:"payload"`
}

type Response struct {
	Version   string          `json:"version"`
	RequestID string          `json:"request_id"`
	OK        bool            `json:"ok"`
	Error     string          `json:"error,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Peer struct {
	PID int32  `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type AuditRecord struct {
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`
	Method    string    `json:"method,omitempty"`
	Peer      Peer      `json:"peer"`
	Allowed   bool      `json:"allowed"`
	Result    string    `json:"result"`
}

type Handler func(context.Context, Peer, json.RawMessage) (interface{}, error)

type ServerOptions struct {
	SocketPath     string
	SocketMode     uint32
	MaxMessageSize int
	Timeout        time.Duration
	ReplayTTL      time.Duration
	MaxReplayIDs   int
	MaxConnections int
	AllowedUIDs    []uint32
	AllowedGIDs    []uint32
	Methods        map[string]Handler
	Audit          func(AuditRecord)
}

type ClientOptions struct {
	SocketPath     string
	MaxMessageSize int
	Timeout        time.Duration
}

type Client struct{ options ClientOptions }

func NewClient(options ClientOptions) (*Client, error) {
	if strings.TrimSpace(options.SocketPath) == "" {
		return nil, errors.New("helper socket path is required")
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
	return &Client{options: options}, nil
}

func (c *Client) Call(ctx context.Context, method string, payload interface{}, result interface{}) error {
	if !validMethod(method) {
		return errors.New("invalid helper method")
	}
	requestID, err := newRequestID()
	if err != nil {
		return err
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode helper payload: %w", err)
	}
	request := Request{Version: ProtocolVersion, RequestID: requestID, Method: method, IssuedAt: time.Now().UTC(), Payload: encodedPayload}
	encodedRequest, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode helper request: %w", err)
	}
	if len(encodedRequest) > c.options.MaxMessageSize {
		return errors.New("helper request exceeds maximum message size")
	}
	dialer := net.Dialer{Timeout: c.options.Timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.options.SocketPath)
	if err != nil {
		return fmt.Errorf("connect helper socket: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(c.options.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if err := writeFrame(connection, encodedRequest, c.options.MaxMessageSize); err != nil {
		return fmt.Errorf("write helper request: %w", err)
	}
	encodedResponse, err := readFrame(connection, c.options.MaxMessageSize)
	if err != nil {
		return fmt.Errorf("read helper response: %w", err)
	}
	var response Response
	if err := decodeStrict(encodedResponse, &response); err != nil {
		return fmt.Errorf("decode helper response: %w", err)
	}
	if response.Version != ProtocolVersion || response.RequestID != requestID {
		return errors.New("helper response binding mismatch")
	}
	if !response.OK {
		if response.Error == "" {
			return errors.New("helper rejected request")
		}
		return errors.New(response.Error)
	}
	if result != nil && len(response.Payload) > 0 {
		if err := decodeStrict(response.Payload, result); err != nil {
			return fmt.Errorf("decode helper result: %w", err)
		}
	}
	return nil
}

func validMethod(method string) bool {
	if method == "" || len(method) > 64 {
		return false
	}
	for _, character := range method {
		if character != '.' && character != '_' && character != '-' && (character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func validRequestID(value string) bool {
	if value == "" || len(value) > maxRequestIDLength {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func newRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate helper request ID: %w", err)
	}
	return "req_" + hex.EncodeToString(value), nil
}

func writeFrame(writer io.Writer, payload []byte, maximum int) error {
	if len(payload) == 0 || len(payload) > maximum {
		return errors.New("invalid helper frame size")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readFrame(reader io.Reader, maximum int) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(header))
	if size <= 0 || size > maximum {
		return nil, errors.New("helper frame exceeds maximum message size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeStrict(content []byte, target interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("unexpected trailing JSON content")
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err == nil {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}
