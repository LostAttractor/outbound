package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

type runtimeTestDialer struct {
	state  *netproxy.StateBroadcaster
	closes atomic.Int32
}

func (d *runtimeTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *runtimeTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *runtimeTestDialer) Connect(context.Context) error { return nil }
func (d *runtimeTestDialer) Snapshot() netproxy.StateEvent { return d.state.Snapshot() }
func (d *runtimeTestDialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.state.WatchState(ctx)
}
func (d *runtimeTestDialer) Close() error {
	d.closes.Add(1)
	d.state.Transition(netproxy.SessionClosed, nil)
	return nil
}

type composingBuilder struct {
	sawParentSession bool
	sawParentCloser  bool
}

type failingBuilder struct {
	child *runtimeTestDialer
	err   error
}

func (b *composingBuilder) Dialer(_ *ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	_, b.sawParentSession = parent.(netproxy.Session)
	_, b.sawParentCloser = parent.(io.Closer)
	return runtimeTestDataPlane{}, nil
}

func (b *failingBuilder) Dialer(*ExtraOption, netproxy.Dialer) (netproxy.Dialer, error) {
	return b.child, b.err
}

type runtimeTestDataPlane struct{}

type capabilityConn struct{ net.Conn }

func (c *capabilityConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (c *capabilityConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (c *capabilityConn) SyscallConn() (syscall.RawConn, error)  { return nil, nil }

type capabilityDialer struct{ conn *capabilityConn }

func (d *capabilityDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func (d *capabilityDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return d.conn, nil
}

func (runtimeTestDataPlane) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (runtimeTestDataPlane) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestBuildRuntimeKeepsParentLifecycleOutOfBuilder(t *testing.T) {
	parentDialer := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	builder := new(composingBuilder)
	runtime, err := BuildRuntime(parentDialer, new(ExtraOption), builder)
	if err != nil {
		t.Fatal(err)
	}
	if builder.sawParentSession || builder.sawParentCloser {
		t.Fatal("builder received the parent's lifecycle capability")
	}
	runtime.Retire()
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := parentDialer.closes.Load(); got != 1 {
		t.Fatalf("parent closes = %d, want 1", got)
	}
}

func TestBuildRuntimeClosesPartialChainOnFailure(t *testing.T) {
	wantErr := errors.New("build failed")
	parent := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	child := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	if _, err := BuildRuntime(parent, new(ExtraOption), &failingBuilder{child: child, err: wantErr}); !errors.Is(err, wantErr) {
		t.Fatalf("BuildRuntime error = %v, want %v", err, wantErr)
	}
	if got := child.closes.Load(); got != 1 {
		t.Fatalf("partial child closes = %d, want 1", got)
	}
	if got := parent.closes.Load(); got != 1 {
		t.Fatalf("parent closes = %d, want 1", got)
	}
}

func TestDataPlanePreservesSyscallAndSeparatesIOPlanes(t *testing.T) {
	conn, peer := net.Pipe()
	firstPeer := peer
	t.Cleanup(func() { _ = firstPeer.Close() })
	view := &dataPlane{dialer: &capabilityDialer{conn: &capabilityConn{Conn: conn}}}
	stream, err := view.DialContext(context.Background(), "udp", "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := stream.(syscall.Conn); !ok {
		t.Fatal("stream view hid syscall.Conn")
	}
	if _, ok := stream.(net.PacketConn); ok {
		t.Fatal("stream view exposed packet-plane methods")
	}
	_ = stream.Close()

	conn, peer = net.Pipe()
	secondPeer := peer
	t.Cleanup(func() { _ = secondPeer.Close() })
	view = &dataPlane{dialer: &capabilityDialer{conn: &capabilityConn{Conn: conn}}}
	packet, err := view.ListenPacket(context.Background(), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := packet.(syscall.Conn); !ok {
		t.Fatal("packet view hid syscall.Conn")
	}
	if _, ok := packet.(net.Conn); ok {
		t.Fatal("packet view exposed stream-plane methods")
	}
	_ = packet.Close()
}
