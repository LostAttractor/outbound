package utils

import (
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

// QStream is a wrapper of *quic.Stream that handles Close() in a way that
// makes more sense to us. By default, *quic.Stream's Close() only closes
// the write side of the stream, not the read side. And if there is unread
// data, the stream is not really considered closed until either the data
// is drained or CancelRead() is called.
// References:
// - https://github.com/libp2p/go-libp2p/blob/master/p2p/transport/quic/stream.go
// - https://github.com/quic-go/quic-go/issues/3558
// - https://github.com/quic-go/quic-go/issues/1599
type QStream struct {
	*quic.Stream
	LAddr net.Addr
	RAddr net.Addr
	Lease *netproxy.Lease
	Fail  func(error)
}

func (s *QStream) DependencyLease() *netproxy.Lease { return s.Lease }
func (s *QStream) WrapError(err error, op netproxy.Operation) error {
	if s.Lease == nil {
		return err
	}
	return common.WrapQUICError(err, s.Lease.Resource(), s.Lease, op, s.Fail)
}
func (s *QStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	return n, s.WrapError(err, netproxy.OpRead)
}
func (s *QStream) Write(p []byte) (int, error) {
	n, err := s.Stream.Write(p)
	return n, s.WrapError(err, netproxy.OpWrite)
}
func (s *QStream) CloseWrite() error { return s.WrapError(s.Stream.Close(), netproxy.OpCloseWrite) }

func (s *QStream) Close() error {
	if s.Lease != nil {
		s.Lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: s.Lease.Resource(), Stream: s.Lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
	}
	s.Stream.CancelRead(0) // Close read
	s.Stream.CancelWrite(0)
	return nil
}

func (s *QStream) LocalAddr() net.Addr  { return s.LAddr }
func (s *QStream) RemoteAddr() net.Addr { return s.RAddr }
