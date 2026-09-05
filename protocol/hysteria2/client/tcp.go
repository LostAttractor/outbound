package client

import (
	"io"
	"net"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
)

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr
	Established      bool
	responseErr      error
}

// TargetDialError is a rejection of one CONNECT request, not a failed QUIC
// connection. Fast-open reports it on the first read instead of DialContext.
type TargetDialError struct{ Message string }

func (e *TargetDialError) Error() string { return "hysteria2 target dial rejected: " + e.Message }
func targetDialError(stream *utils.QStream, message string) error {
	metadata := netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Phase: netproxy.OpDial, Origin: netproxy.OriginTarget, Reason: netproxy.ReasonRejected}
	if stream.Lease != nil {
		metadata.Resource, metadata.Stream = stream.Lease.Resource(), stream.Lease.Stream()
	}
	err := netproxy.WrapFailure(&TargetDialError{Message: message}, metadata)
	if stream.Lease != nil {
		stream.Lease.Invalidate(err)
	}
	return err
}
func (c *tcpConn) DependencyLease() *netproxy.Lease { return c.Orig.DependencyLease() }

func responseError(stream *utils.QStream, err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	err = stream.WrapError(err, netproxy.OpRead)
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope == netproxy.ScopeUnknown || failure.Scope == "" {
		failure.Scope, failure.Layer, failure.Reason = netproxy.ScopeStream, netproxy.LayerProxy, netproxy.ReasonProtocol
		if stream.Lease != nil {
			failure.Resource, failure.Stream = stream.Lease.Resource(), stream.Lease.Stream()
		}
		err = netproxy.WrapFailure(err, failure)
	}
	if failure.Scope == netproxy.ScopeStream && stream.Lease != nil {
		stream.Lease.Invalidate(err)
	}
	return err
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	if c.responseErr != nil {
		return 0, c.responseErr
	}
	if !c.Established {
		// Read response
		ok, msg, err := protocol.ReadTCPResponse(c.Orig)
		if err != nil {
			c.responseErr = responseError(c.Orig, err)
			return 0, c.responseErr
		}
		if !ok {
			c.responseErr = targetDialError(c.Orig, msg)
			return 0, c.responseErr
		}
		c.Established = true
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	return c.Orig.Write(b)
}

func (c *tcpConn) Close() error {
	return c.Orig.Close()
}

// CloseWrite sends a QUIC FIN while leaving the receive side open.
func (c *tcpConn) CloseWrite() error {
	return c.Orig.CloseWrite()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return c.Orig.SetDeadline(t)
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	return c.Orig.SetReadDeadline(t)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}
