package smux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"github.com/xtaci/smux"
)

type Conn struct {
	net.Conn

	addr       string
	udp        bool
	packetAddr bool

	onceRead  bool
	onceWrite bool
}

func ReadResponse(conn net.Conn) (err error) {
	var status uint8
	err = binary.Read(conn, binary.BigEndian, &status)
	if err != nil {
		return
	}
	if status == statusError {
		var message []byte
		message, err = io.ReadAll(conn)
		if err != nil {
			return
		}
		return netproxy.WrapFailure(errors.New(fmt.Sprintf("smux target rejected connection: %s", message)), netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerSMUX, Origin: netproxy.OriginTarget, Reason: netproxy.ReasonRejected, Phase: netproxy.OpDial})
	}
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.onceRead {
		err = ReadResponse(c.Conn)
		if err != nil {
			return
		}
		c.onceRead = true
	}
	return c.Conn.Read(b)
}

type StreamRequest struct {
	Destination string
	UDP         bool
	PacketAddr  bool
}

func WriteStreamRequest(buf *bytes.Buffer, streamRequest *StreamRequest) error {
	var flags uint16
	if streamRequest.UDP {
		flags |= flagUDP
	}
	if streamRequest.PacketAddr {
		flags |= flagAddr
	}
	binary.Write(buf, binary.BigEndian, flags)
	return socks5.WriteAddr(streamRequest.Destination, buf)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if !c.onceWrite {
		err = WriteStreamRequest(buf, &StreamRequest{
			Destination: c.addr,
			UDP:         c.udp,
			PacketAddr:  c.packetAddr,
		})
		if err != nil {
			return
		}
		c.onceWrite = true
	}
	buf.Write(b)
	_, err = c.Conn.Write(buf.Bytes())
	return len(b), err
}

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }

type leasedStream struct {
	*smux.Stream
	handle *netproxy.SingleSessionHandle[*smuxResource]
	lease  *netproxy.Lease
}

func (c *leasedStream) DependencyLease() *netproxy.Lease { return c.lease }
func (c *leasedStream) failure(err error, phase netproxy.Operation) error {
	if err == nil {
		return nil
	}
	fact := netproxy.ClassifyFailure(err)
	cause := c.handle.Resource().monitor.cause()
	if cause != nil {
		err = cause
		fact = netproxy.ClassifyFailure(cause)
		fact.Scope = netproxy.ScopeSharedResource
	} else if err == io.EOF && phase == netproxy.OpRead {
		return io.EOF
	} else if fact.Scope == netproxy.ScopeUnknown {
		fact.Scope = netproxy.ScopeStream
	}
	fact.Resource, fact.Stream, fact.Phase = c.handle.Ref(), c.lease.Stream(), phase
	if fact.Layer == netproxy.LayerUnknown {
		fact.Layer = netproxy.LayerSMUX
	}
	wrapped := netproxy.WrapFailure(err, fact)
	if fact.Scope == netproxy.ScopeSharedResource {
		c.handle.Abort(wrapped)
	} else if fact.Scope == netproxy.ScopeStream {
		c.lease.Invalidate(wrapped)
	}
	return wrapped
}
func (c *leasedStream) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	return n, c.failure(err, netproxy.OpRead)
}
func (c *leasedStream) Write(p []byte) (int, error) {
	n, err := c.Stream.Write(p)
	return n, c.failure(err, netproxy.OpWrite)
}
func (c *leasedStream) Close() error {
	c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: c.handle.Ref(), Stream: c.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerSMUX, Origin: netproxy.OriginLocalCleanup}))
	return c.Stream.Close()
}
