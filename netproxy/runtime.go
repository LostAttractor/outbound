package netproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"syscall"
)

// Runtime owns one fully constructed outbound chain. Retire rejects new work
// and releases the chain after all operations and returned connections drain.
type Runtime struct {
	owned   Dialer
	dialer  Dialer
	session Session
	closer  io.Closer

	mu        sync.Mutex
	refs      int
	retired   bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
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

type runtimeSyscallConn struct {
	*runtimeConn
	raw syscall.Conn
}

func (c *runtimeSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

type runtimeCloseWriteSyscallConn struct {
	*runtimeSyscallConn
	closeWriter CloseWriter
}

func (c *runtimeCloseWriteSyscallConn) CloseWrite() error {
	return c.closeWriter.CloseWrite()
}

type runtimeSyscallPacketConn struct {
	*runtimePacketConn
	raw syscall.Conn
}

func (c *runtimeSyscallPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

func (s *runtimeSession) Connect(ctx context.Context) error {
	r := s.runtime
	if !r.acquire() {
		return net.ErrClosed
	}
	defer r.release()
	if err := s.Session.Connect(ctx); err != nil {
		return err
	}
	if !r.accepting() {
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
	closeWriter, hasCloseWriter := conn.(CloseWriter)
	raw, hasSyscallConn := conn.(syscall.Conn)
	if hasSyscallConn {
		withSyscall := &runtimeSyscallConn{runtimeConn: tracked, raw: raw}
		if hasCloseWriter {
			return &runtimeCloseWriteSyscallConn{runtimeSyscallConn: withSyscall, closeWriter: closeWriter}, nil
		}
		return withSyscall, nil
	}
	if hasCloseWriter {
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
	tracked := &runtimePacketConn{PacketConn: conn, release: sync.OnceFunc(r.release)}
	if raw, ok := conn.(syscall.Conn); ok {
		return &runtimeSyscallPacketConn{runtimePacketConn: tracked, raw: raw}, nil
	}
	return tracked, nil
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
	runtime := &Runtime{owned: owned, done: make(chan struct{})}
	runtime.dialer = &runtimeDialer{runtime: runtime}
	runtime.closer, _ = owned.(io.Closer)
	if session, ok := owned.(SessionOwner); ok {
		runtime.session = &runtimeSession{Session: session, runtime: runtime}
	}
	return runtime
}

// Dialer returns the data-plane view. It does not expose Session or ownership.
func (r *Runtime) Dialer() Dialer { return r.dialer }

// Session returns the optional shared-connection controller. Runtime remains
// the sole owner of its closure.
func (r *Runtime) Session() (Session, bool) { return r.session, r.session != nil }

func (r *Runtime) acquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.retired {
		return false
	}
	r.refs++
	return true
}

func (r *Runtime) accepting() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.retired
}

func (r *Runtime) release() {
	r.mu.Lock()
	r.refs--
	closeOwned := r.retired && r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.startClose()
	}
}

func (r *Runtime) startClose() {
	r.closeOnce.Do(func() {
		go r.closeOwned()
	})
}

func (r *Runtime) closeOwned() {
	var err error
	if r.closer != nil {
		err = r.closer.Close()
	}
	r.mu.Lock()
	r.closeErr = err
	r.mu.Unlock()
	close(r.done)
}

func (r *Runtime) waitErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeErr
}

// Retire rejects new operations. Resource cleanup runs after the last active
// operation or returned connection releases its implicit lease.
func (r *Runtime) Retire() {
	r.mu.Lock()
	r.retired = true
	closeOwned := r.refs == 0
	r.mu.Unlock()
	if closeOwned {
		r.startClose()
	}
}

// Wait waits for a retired Runtime to finish releasing its owned chain.
func (r *Runtime) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return r.waitErr()
	default:
	}
	select {
	case <-r.done:
		return r.waitErr()
	case <-ctx.Done():
		select {
		case <-r.done:
			return r.waitErr()
		default:
			return ctx.Err()
		}
	}
}
