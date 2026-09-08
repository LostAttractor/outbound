package protocol

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
)

// NewPacketAssociation adapts protocols whose UDP streams carry one fixed
// destination. All targets use the same dialer and share one caller lifetime;
// neither destination changes nor substream creation select another node.
func NewPacketAssociation(ctx context.Context, address string, open func(context.Context, string) (net.PacketConn, error)) (net.PacketConn, error) {
	first, err := open(ctx, address)
	if err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &packetAssociation{
		ctx: lifetime, cancel: cancel, open: open, local: first.LocalAddr(),
		lease: netproxy.NewLease(netproxy.ResourceRef{}),
		conns: make(map[string]net.PacketConn), incoming: make(chan receivedPacket),
		writeGate: make(chan struct{}, 1), readDeadline: MakeDeadline(), writeDeadline: MakeDeadline(),
	}
	c.writeGate <- struct{}{}
	c.add(address, first)
	if !netproxy.DependencyOf(first).Valid() {
		_ = c.Close()
		return nil, netproxy.DependencyOf(first).Cause()
	}
	return c, nil
}

type receivedPacket struct {
	data []byte // ownership passes from the reader to ReadFrom
	from net.Addr
	err  error
}

type packetAssociation struct {
	ctx    context.Context
	cancel context.CancelFunc
	open   func(context.Context, string) (net.PacketConn, error)
	local  net.Addr
	lease  *netproxy.Lease

	mu            sync.Mutex
	conns         map[string]net.PacketConn
	writeUntil    time.Time
	writeGate     chan struct{}
	readDeadline  Deadline
	writeDeadline Deadline
	incoming      chan receivedPacket
	readers       sync.WaitGroup
	closeOnce     sync.Once
	closeErr      error
}

// Caller holds mu, except while constructing an unpublished association.
func (c *packetAssociation) add(address string, conn net.PacketConn) {
	c.conns[address] = conn
	c.readers.Go(func() { c.readPackets(conn) })
	if dependency := netproxy.DependencyOf(conn); dependency != nil {
		go func() {
			select {
			case <-c.ctx.Done():
			case <-dependency.Done():
				if cause := dependency.AbortCause(); cause != nil {
					c.lease.Abort(cause)
					_ = c.Close()
				}
			}
		}()
	}
}

func (c *packetAssociation) readPackets(conn net.PacketConn) {
	var terminal error
	for {
		packet := receivedPacket{err: terminal}
		if terminal == nil {
			buf := pool.GetBuffer(65535)
			n, from, err := conn.ReadFrom(buf)
			packet = receivedPacket{data: buf[:n], from: from, err: err}
			var timeout net.Error
			if err != nil && !errors.Is(err, io.ErrShortBuffer) && !(errors.As(err, &timeout) && timeout.Timeout()) {
				terminal = err
			}
		}
		select {
		case c.incoming <- packet:
		case <-c.ctx.Done():
			pool.PutBuffer(packet.data)
			return
		}
	}
}

func (c *packetAssociation) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case packet := <-c.incoming:
		n := copy(p, packet.data)
		if n < len(packet.data) && packet.err == nil {
			packet.err = io.ErrShortBuffer
		}
		pool.PutBuffer(packet.data)
		return n, packet.from, packet.err
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *packetAssociation) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("UDP destination is required")
	}
	select {
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	select {
	case <-c.writeGate:
		defer func() { c.writeGate <- struct{}{} }()
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-c.writeDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	conn := c.conns[addr.String()]
	c.mu.Unlock()
	if conn == nil {
		// Opening a new target obeys Close and changes to the write deadline.
		ctx, cancel := netproxy.NewDialTimeoutContextFrom(c.ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-ctx.Done():
			case <-c.writeDeadline.Wait():
				cancel()
			}
		}()
		var err error
		conn, err = c.open(ctx, addr.String())
		if err == nil {
			err = ctx.Err()
		}
		cancel()
		<-done
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			select {
			case <-c.writeDeadline.Wait():
				return 0, os.ErrDeadlineExceeded
			default:
				return 0, err
			}
		}
		c.mu.Lock()
		if c.ctx.Err() != nil {
			c.mu.Unlock()
			_ = conn.Close()
			return 0, net.ErrClosed
		}
		if dependency := netproxy.DependencyOf(conn); !dependency.Valid() {
			c.mu.Unlock()
			if cause := dependency.AbortCause(); cause != nil {
				c.lease.Abort(cause)
				go c.Close()
			}
			_ = conn.Close()
			return 0, dependency.Cause()
		}
		_ = conn.SetWriteDeadline(c.writeUntil)
		c.add(addr.String(), conn)
		c.mu.Unlock()
	}
	return conn.WriteTo(p, addr)
}

func (c *packetAssociation) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.mu.Lock()
		conns := c.conns
		c.conns = nil
		c.mu.Unlock()
		// Preserve a child owner's signal even if its watcher has not run yet.
		for _, conn := range conns {
			if cause := netproxy.DependencyOf(conn).AbortCause(); cause != nil {
				c.lease.Abort(cause)
			}
		}
		c.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Scope: netproxy.ScopeStream, Origin: netproxy.OriginLocalCleanup}))
		for _, conn := range conns {
			c.closeErr = errors.Join(c.closeErr, conn.Close())
		}
		// A canceled target open must finish before the Runtime releases its
		// last reference to the dialer used by this association.
		<-c.writeGate
		c.writeGate <- struct{}{}
		c.readers.Wait()
		c.readDeadline.Set(time.Time{})
		c.writeDeadline.Set(time.Time{})
	})
	return c.closeErr
}

func (c *packetAssociation) DependencyLease() *netproxy.Lease { return c.lease }
func (c *packetAssociation) LocalAddr() net.Addr              { return c.local }
func (c *packetAssociation) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *packetAssociation) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}
func (c *packetAssociation) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeUntil = t
	c.writeDeadline.Set(t)
	var err error
	for _, conn := range c.conns {
		err = errors.Join(err, conn.SetWriteDeadline(t))
	}
	return err
}
