package netproxy

import (
	"context"
	"io"
	"net"
	"sync"
)

// Runtime owns one constructed outbound chain. Session is nil for stateless
// chains; Close always releases every resource retained by the chain.
type Runtime struct {
	Dialer  Dialer
	Session Session

	owned  Dialer
	closer io.Closer

	mu        sync.Mutex
	refs      int
	closing   bool
	ownedOnce sync.Once
	err       error
}

type runtimeSession struct {
	Session
	runtime *Runtime
}

type runtimeDialer struct{ runtime *Runtime }

type runtimeConn struct {
	net.Conn
	release func()
}

type runtimePacketConn struct {
	net.PacketConn
	release func()
}

func (s *runtimeSession) Close() error { return s.runtime.Close() }

func (s *runtimeSession) Connect(ctx context.Context) error {
	if !s.runtime.accepting() {
		return net.ErrClosed
	}
	if err := s.Session.Connect(ctx); err != nil {
		return err
	}
	if !s.runtime.accepting() {
		return net.ErrClosed
	}
	return nil
}

func (d *runtimeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r := d.runtime
	if !r.acquire() {
		return nil, net.ErrClosed
	}
	conn, err := r.owned.DialContext(ctx, network, address)
	if err != nil {
		r.release()
		return nil, err
	}
	if !r.accepting() {
		_ = conn.Close()
		r.release()
		return nil, net.ErrClosed
	}
	tracked := &runtimeConn{Conn: conn, release: sync.OnceFunc(r.release)}
	if closeWriter, ok := conn.(CloseWriter); ok {
		return &CloseWriteConn{Conn: tracked, CloseWriter: closeWriter}, nil
	}
	return tracked, nil
}

func (d *runtimeDialer) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	r := d.runtime
	if !r.acquire() {
		return nil, net.ErrClosed
	}
	conn, err := r.owned.ListenPacket(ctx, address)
	if err != nil {
		r.release()
		return nil, err
	}
	if !r.accepting() {
		_ = conn.Close()
		r.release()
		return nil, net.ErrClosed
	}
	return &runtimePacketConn{PacketConn: conn, release: sync.OnceFunc(r.release)}, nil
}

func (c *runtimeConn) Close() error {
	defer c.release()
	return c.Conn.Close()
}

func (c *runtimePacketConn) Close() error {
	defer c.release()
	return c.PacketConn.Close()
}

func NewRuntime(owned Dialer) *Runtime {
	runtime := &Runtime{owned: owned}
	runtime.Dialer = &runtimeDialer{runtime: runtime}
	runtime.closer, _ = owned.(io.Closer)
	if session, ok := owned.(Session); ok {
		runtime.Session = &runtimeSession{Session: session, runtime: runtime}
	}
	return runtime
}

// ComposeRuntime adds a data-plane layer and transfers ownership of parent to
// the returned Runtime. The data-plane Dialer remains independent from the
// optional Session capability.
func ComposeRuntime(dialer Dialer, parent *Runtime) *Runtime {
	if parent == nil {
		return NewRuntime(dialer)
	}
	return NewRuntime(ComposeDialer(dialer, parent.owned))
}

func (r *Runtime) acquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return false
	}
	if r.closer != nil {
		r.refs++
	}
	return true
}

func (r *Runtime) accepting() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.closing
}

func (r *Runtime) release() {
	if r.closer == nil {
		return
	}
	r.mu.Lock()
	r.refs--
	closeOwned := r.closing && r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.closeOwned()
	}
}

func (r *Runtime) closeOwned() {
	r.ownedOnce.Do(func() {
		err := r.closer.Close()
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
	})
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	r.closing = true
	closeOwned := r.closer != nil && r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.closeOwned()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
