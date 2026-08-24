package smux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/xtaci/smux"
)

const (
	ProtocolSmux = iota
	ProtocolYAMux
	ProtocolH2Mux
)

const (
	Version0 = iota
	Version1
)

const (
	flagUDP       = 0b01
	flagAddr      = 0b10
	statusSuccess = 0
	statusError   = 1
)

const (
	smuxFrameHeaderSize   = 8
	smuxCommandPSH        = 2
	smuxCommandUPD        = 4
	smuxUpdatePayloadSize = 8
)

type Smux struct {
	Dialer         netproxy.Dialer
	PassthroughUdp bool

	initOnce  sync.Once
	lifecycle *netproxy.SingleSession[*smuxResource]
}

type smuxResource struct {
	session *smux.Session
	monitor *monitoredConn
}

type monitoredConn struct {
	net.Conn
	reportOnce       sync.Once
	failed           chan error
	broken           atomic.Bool
	expectedVersion  byte
	header           [smuxFrameHeaderSize]byte
	headerRead       int
	payloadRemaining int
}

func (c *monitoredConn) report(err error) {
	if err != nil {
		c.broken.Store(true)
		c.reportOnce.Do(func() {
			select {
			case c.failed <- err:
			default:
			}
		})
	}
}

func (c *monitoredConn) inspectRead(p []byte) {
	for len(p) > 0 && !c.broken.Load() {
		if c.payloadRemaining > 0 {
			n := min(len(p), c.payloadRemaining)
			c.payloadRemaining -= n
			p = p[n:]
			continue
		}
		n := copy(c.header[c.headerRead:], p)
		c.headerRead += n
		p = p[n:]
		if c.headerRead < len(c.header) {
			continue
		}

		version := c.header[0]
		command := c.header[1]
		length := int(binary.LittleEndian.Uint16(c.header[2:4]))
		c.headerRead = 0
		if version != c.expectedVersion || command > smuxCommandUPD {
			c.report(smux.ErrInvalidProtocol)
			return
		}
		switch command {
		case smuxCommandPSH:
			c.payloadRemaining = length
		case smuxCommandUPD:
			c.payloadRemaining = smuxUpdatePayloadSize
		}
	}
}

func (c *monitoredConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.inspectRead(p[:n])
	c.report(err)
	return n, err
}

func (c *monitoredConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.report(err)
	return n, err
}

var _ netproxy.StatefulDialer = (*Smux)(nil)

type SmuxConfig struct {
	PassThroughUDP bool
}

func (s *SmuxConfig) Dialer(option *dialer.ExtraOption, nextDialer netproxy.Dialer) (netproxy.Dialer, error) {
	return &Smux{
		Dialer:         nextDialer,
		PassthroughUdp: s.PassThroughUDP,
	}, nil
}

func (s *Smux) session() *netproxy.SingleSession[*smuxResource] {
	s.initOnce.Do(func() {
		s.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*smuxResource]{
			Establish: s.establish,
			IsConnected: func(resource *smuxResource) bool {
				return !resource.monitor.broken.Load() && !resource.session.IsClosed()
			},
			Observe: s.observe,
			Close: func(resource *smuxResource) error {
				err := resource.session.Close()
				if errors.Is(err, io.ErrClosedPipe) {
					return nil
				}
				return err
			},
		})
	})
	return s.lifecycle
}

func (s *Smux) Snapshot() netproxy.StateEvent {
	return s.session().Snapshot()
}

func (s *Smux) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return s.session().WatchState(ctx)
}

func (s *Smux) Connect(ctx context.Context) error {
	return s.session().Connect(ctx)
}

func (s *Smux) establish(ctx context.Context) (*smuxResource, error) {
	conn, err := s.Dialer.DialContext(ctx, "tcp", "sp.mux.sing-box.arpa:444")
	if err != nil {
		return nil, err
	}
	_, err = common.Invoke(ctx, func() (any, error) {
		return conn.Write([]byte{Version0, ProtocolSmux})
	}, func() {
		_ = conn.Close()
	})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	config := smux.DefaultConfig()
	monitored := &monitoredConn{
		Conn:            conn,
		failed:          make(chan error, 1),
		expectedVersion: byte(config.Version),
	}
	session, err := smux.Client(monitored, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &smuxResource{session: session, monitor: monitored}, nil
}

func (s *Smux) currentSession() (*smux.Session, error) {
	resource, err := s.session().Current()
	if err != nil {
		return nil, err
	}
	return resource.session, nil
}

func openStream(ctx context.Context, session *smux.Session) (*smux.Stream, error) {
	type result struct {
		stream *smux.Stream
		err    error
	}
	results := make(chan result)
	go func() {
		stream, err := session.OpenStream()
		select {
		case results <- result{stream: stream, err: err}:
		case <-ctx.Done():
			if stream != nil {
				_ = stream.Close()
			}
		}
	}()
	select {
	case result := <-results:
		if err := ctx.Err(); err != nil {
			if result.stream != nil {
				_ = result.stream.Close()
			}
			return nil, err
		}
		return result.stream, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Smux) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	if network == "udp" && s.PassthroughUdp {
		return s.Dialer.DialContext(ctx, network, addr)
	}
	session, err := s.currentSession()
	if err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		stream, err := openStream(ctx, session)
		if err != nil {
			return nil, err
		}
		return &Conn{Conn: stream, addr: addr}, nil
	case "udp":
		conn, err := s.ListenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Smux) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.PassthroughUdp {
		return s.Dialer.ListenPacket(ctx, addr)
	}
	session, err := s.currentSession()
	if err != nil {
		return nil, err
	}
	stream, err := openStream(ctx, session)
	if err != nil {
		return nil, err
	}
	return &UDPConn{Conn: Conn{Conn: stream, addr: addr, udp: true, packetAddr: true}}, nil
}

func (s *Smux) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*smuxResource]) {
	resource := handle.Resource()
	var cause error
	select {
	case <-ctx.Done():
		return
	case <-resource.session.CloseChan():
		cause = net.ErrClosed
	case cause = <-resource.monitor.failed:
	}
	handle.Disconnect(cause)
}

func (s *Smux) Close() error {
	return s.session().Close()
}
