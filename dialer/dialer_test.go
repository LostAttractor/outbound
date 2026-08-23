package dialer

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
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

type composingBuilder struct{ sawParentSession bool }

func (b *composingBuilder) Dialer(_ *ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	_, b.sawParentSession = parent.(netproxy.Session)
	return netproxy.ComposeDialer(runtimeTestDataPlane{}, parent), nil
}

type runtimeTestDataPlane struct{}

func (runtimeTestDataPlane) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (runtimeTestDataPlane) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestBuildRuntimeKeepsParentLifecycleOutOfBuilder(t *testing.T) {
	parentDialer := &runtimeTestDialer{state: netproxy.NewStateBroadcaster(netproxy.SessionConnected)}
	parent := netproxy.NewRuntime(parentDialer)
	builder := new(composingBuilder)
	runtime, err := BuildRuntime(builder, new(ExtraOption), parent)
	if err != nil {
		t.Fatal(err)
	}
	if builder.sawParentSession {
		t.Fatal("builder received the parent's Session capability")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := parentDialer.closes.Load(); got != 1 {
		t.Fatalf("parent closes = %d, want 1", got)
	}
}
