package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.RegisterLayer("anytls", func(parent netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
		dialer, err := NewDialer(parent, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		return netproxy.Layer{
			Data:      dialer,
			Sessions:  []netproxy.Session{dialer},
			Resources: []io.Closer{dialer},
		}, nil
	})
}

type Dialer struct {
	protocol.StatelessDialer
	proxyAddress string
	key          []byte
	tlsConfig    *tls.Config

	idleSessionLock sync.Mutex
	idleSessions    map[*session]struct{}
	sessions        map[*session]struct{}
	ctx             context.Context
	cancel          context.CancelFunc
	operations      sync.WaitGroup
	workers         sync.WaitGroup
	closeOnce       sync.Once
	closeErr        error

	connectToken chan struct{}
	state        *netproxy.StateBroadcaster
}

func NewDialer(ParentDialer netproxy.Dialer, header protocol.Header) (*Dialer, error) {
	sum := sha256.Sum256([]byte(header.Password))
	ctx, cancel := context.WithCancel(context.Background())
	return &Dialer{
		ParentDialer: ParentDialer,
		proxyAddress: header.ProxyAddress,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
		idleSessions: make(map[*session]struct{}),
		sessions:     make(map[*session]struct{}),
		connectToken: make(chan struct{}, 1),
		state:        netproxy.NewStateBroadcaster(netproxy.SessionDisconnected),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

func (d *Dialer) Snapshot() netproxy.StateEvent { return d.state.Snapshot() }

func (d *Dialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.state.WatchState(ctx)
}

func (d *Dialer) begin(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		return nil, nil, net.ErrClosed
	}
	d.operations.Add(1)
	d.idleSessionLock.Unlock()

	operationCtx, cancel := context.WithCancel(ctx)
	stopClose := context.AfterFunc(d.ctx, cancel)
	return operationCtx, func() {
		stopClose()
		cancel()
		d.operations.Done()
	}, nil
}

func (d *Dialer) contextError(ctx context.Context) error {
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	return ctx.Err()
}

func (d *Dialer) Connect(ctx context.Context) error {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return err
	}
	defer finish()
	select {
	case d.connectToken <- struct{}{}:
		defer func() { <-d.connectToken }()
	case <-ctx.Done():
		return d.contextError(ctx)
	}
	if err := ctx.Err(); err != nil {
		return d.contextError(ctx)
	}
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		return net.ErrClosed
	}
	if d.state.Snapshot().State == netproxy.SessionConnected {
		if ctx.Err() != nil {
			d.idleSessionLock.Unlock()
			return d.contextError(ctx)
		}
		d.idleSessionLock.Unlock()
		return nil
	}
	d.state.Transition(netproxy.SessionConnecting, nil)
	d.idleSessionLock.Unlock()
	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	s, err := d.createSession(dialCtx)
	cancel()
	if err != nil {
		return d.sessionError(err)
	}
	d.idleSessionLock.Lock()
	_, alive := d.sessions[s]
	operationErr := ctx.Err()
	if operationErr == nil && alive && !s.closed.Load() {
		d.idleSessions[s] = struct{}{}
	}
	d.idleSessionLock.Unlock()
	if operationErr != nil {
		_ = s.Close()
		return d.contextError(ctx)
	}
	if !alive || s.closed.Load() {
		return d.sessionError(netproxy.ErrNotConnected)
	}
	return nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	switch network {
	case "tcp":
		s, err := d.getSession(ctx)
		if err != nil {
			return nil, err
		}
		return d.openContext(ctx,
			func() (net.Conn, error) { return s.newStream(addr) },
			func() { _ = s.Close() })
	case "udp":
		conn, err := d.listenPacket(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr(network, addr),
		}, nil
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	ctx, finish, err := d.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	return d.listenPacket(ctx, addr)
}

func (d *Dialer) listenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	s, err := d.getSession(ctx)
	if err != nil {
		return nil, err
	}
	return d.openContext(ctx,
		func() (net.PacketConn, error) {
			return s.newPacketStream(net.JoinHostPort("sp.v2.udp-over-tcp.arpa", port), addr)
		},
		func() { _ = s.Close() })
}

func (d *Dialer) openContext[T interface{ Close() error }](ctx context.Context, open func() (T, error), abort func()) (T, error) {
	type result struct {
		value T
		err   error
	}
	results := make(chan result)
	d.workers.Go(func() {
		value, err := open()
		select {
		case results <- result{value: value, err: err}:
		case <-ctx.Done():
			if err == nil {
				_ = value.Close()
			}
		}
	})
	select {
	case result := <-results:
		if result.err != nil {
			abort()
			var zero T
			return zero, result.err
		}
		if err := ctx.Err(); err != nil {
			_ = result.value.Close()
			var zero T
			return zero, err
		}
		return result.value, nil
	case <-ctx.Done():
		abort()
		var zero T
		return zero, ctx.Err()
	}
}

func (d *Dialer) getSession(ctx context.Context) (*session, error) {
	if err := netproxy.RequireConnected(d); err != nil {
		return nil, err
	}
	d.idleSessionLock.Lock()
	for s := range d.idleSessions {
		delete(d.idleSessions, s)
		if s.closed.Load() {
			continue
		}
		d.idleSessionLock.Unlock()
		return s, nil
	}
	d.idleSessionLock.Unlock()

	return d.createSession(ctx)
}

func (d *Dialer) createSession(ctx context.Context) (*session, error) {
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.proxyAddress)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, d.tlsConfig)
	stopClose := context.AfterFunc(ctx, func() { _ = tlsConn.Close() })
	defer stopClose()

	buf := pool.GetBuffer(len(d.key) + 2)
	defer pool.PutBuffer(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	if _, err := tlsConn.Write(buf); err != nil {
		tlsConn.Close()
		return nil, err
	}

	s := newSession(tlsConn, d.sessionIdle)
	d.idleSessionLock.Lock()
	if d.ctx.Err() != nil {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	d.sessions[s] = struct{}{}
	d.state.Transition(netproxy.SessionConnected, nil)
	d.idleSessionLock.Unlock()
	d.workers.Go(func() {
		err := s.run()
		d.sessionClosed(s, err)
	})

	return s, nil
}

func (d *Dialer) sessionIdle(s *session) {
	d.idleSessionLock.Lock()
	if _, exists := d.sessions[s]; d.ctx.Err() == nil && exists && !s.closed.Load() {
		d.idleSessions[s] = struct{}{}
	}
	d.idleSessionLock.Unlock()
}

func (d *Dialer) sessionClosed(s *session, cause error) {
	d.idleSessionLock.Lock()
	delete(d.idleSessions, s)
	delete(d.sessions, s)
	disconnected := len(d.sessions) == 0 && d.ctx.Err() == nil
	if disconnected {
		d.state.Transition(netproxy.SessionDisconnected, cause)
	}
	d.idleSessionLock.Unlock()
}

func (d *Dialer) sessionError(cause error) error {
	d.idleSessionLock.Lock()
	defer d.idleSessionLock.Unlock()
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(d.sessions) == 0 {
		d.state.Transition(netproxy.SessionDisconnected, cause)
	}
	return cause
}

func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.idleSessionLock.Lock()
		d.cancel()
		sessions := make([]*session, 0, len(d.sessions))
		for session := range d.sessions {
			sessions = append(sessions, session)
		}
		clear(d.idleSessions)
		clear(d.sessions)
		d.state.Transition(netproxy.SessionClosed, nil)
		d.idleSessionLock.Unlock()
		for _, session := range sessions {
			d.closeErr = errors.Join(d.closeErr, session.Close())
		}
		d.operations.Wait()
		d.workers.Wait()
	})
	return d.closeErr
}
