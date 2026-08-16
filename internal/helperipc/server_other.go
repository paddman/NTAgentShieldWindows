//go:build !linux

package helperipc

type Server struct{}

func NewServer(ServerOptions) (*Server, error) { return nil, ErrUnsupported }
