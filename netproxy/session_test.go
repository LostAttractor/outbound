package netproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type testDialer struct{}

func (testDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (testDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

type testResourceDialer struct {
	testDialer
	closes atomic.Int32
}

type orderedResourceDialer struct {
	testDialer
	name  string
	order *[]string
}

type packetCapableTestConn struct{ net.Conn }

func (c *packetCapableTestConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *packetCapableTestConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

type streamTestDialer struct {
	testDialer
	conn net.Conn
}

func (d *streamTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

type packetTestDialer struct {
	testDialer
	conn net.PacketConn
}

func (d *packetTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return d.conn, nil
}

type ownedTestDialer struct {
	Dialer
	closes atomic.Int32
}

func (d *ownedTestDialer) Close() error {
	d.closes.Add(1)
	return nil
}

type orderedSession struct {
	*testSession
	name  string
	order *[]string
}

func (s *orderedSession) Close() error {
	*s.order = append(*s.order, s.name)
	return s.testSession.Close()
}

type testSession struct{ state *StateBroadcaster }

type blockingCloseSession struct {
	*testSession
	started chan struct{}
	release chan struct{}
	err     error
}

func (s *blockingCloseSession) Close() error {
	close(s.started)
	<-s.release
	_ = s.testSession.Close()
	return s.err
}

type blockingConnectSession struct {
	*testSession
	started chan struct{}
	release chan struct{}
}

func (s *blockingConnectSession) Connect(context.Context) error {
	close(s.started)
	<-s.release
	s.state.Transition(SessionConnected, nil)
	return nil
}

func newTestSession() *testSession {
	return &testSession{state: NewStateBroadcaster(SessionDisconnected)}
}
func (s *testSession) Connect(context.Context) error {
	s.state.Transition(SessionConnecting, nil)
	s.state.Transition(SessionConnected, nil)
	return nil
}
func (s *testSession) Snapshot() StateEvent { return s.state.Snapshot() }
func (s *testSession) WatchState(ctx context.Context) <-chan StateEvent {
	return s.state.WatchState(ctx)
}
func (s *testSession) Close() error {
	s.state.Transition(SessionClosed, nil)
	return nil
}

func (d *testResourceDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func (d *orderedResourceDialer) Close() error {
	*d.order = append(*d.order, d.name)
	return nil
}

func TestStateBroadcasterPublishesEveryTransitionToEveryWatcher(t *testing.T) {
	b := NewStateBroadcaster(SessionDisconnected)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := b.WatchState(ctx)
	bw := b.WatchState(ctx)

	b.Transition(SessionConnecting, nil)
	b.Transition(SessionConnected, nil)
	b.Transition(SessionDisconnected, context.Canceled)

	want := []SessionState{SessionDisconnected, SessionConnecting, SessionConnected, SessionDisconnected}
	for name, watcher := range map[string]<-chan StateEvent{"a": a, "b": bw} {
		for i, state := range want {
			select {
			case event := <-watcher:
				if event.Seq != uint64(i) || event.State != state {
					t.Fatalf("%s event %d = (%d, %s), want (%d, %s)", name, i, event.Seq, event.State, i, state)
				}
			case <-time.After(time.Second):
				t.Fatalf("timed out waiting for %s event %d", name, i)
			}
		}
	}
}

func TestStateBroadcasterClosedIsTerminal(t *testing.T) {
	b := NewStateBroadcaster(SessionDisconnected)
	b.Transition(SessionClosed, nil)
	if b.Transition(SessionConnected, nil) {
		t.Fatal("transition succeeded after closed")
	}
	events := b.WatchState(context.Background())
	event, ok := <-events
	if !ok || event.State != SessionClosed {
		t.Fatalf("first event = %#v, %v", event, ok)
	}
	if _, ok := <-events; ok {
		t.Fatal("watch channel remained open after closed snapshot")
	}
}

func TestStateBroadcasterConcurrentTransitionsStayOrdered(t *testing.T) {
	b := NewStateBroadcaster(SessionDisconnected)
	events := b.WatchState(context.Background())
	start := make(chan struct{})
	done := make(chan struct{}, 256)
	for i := 0; i < cap(done); i++ {
		state := SessionConnecting
		if i%2 == 0 {
			state = SessionConnected
		}
		go func() {
			<-start
			b.Transition(state, nil)
			done <- struct{}{}
		}()
	}
	close(start)
	for i := 0; i < cap(done); i++ {
		<-done
	}
	b.Transition(SessionClosed, nil)

	var seq uint64
	for event := range events {
		if event.Seq != seq {
			t.Fatalf("event sequence = %d, want %d", event.Seq, seq)
		}
		seq++
	}
	if seq < 2 {
		t.Fatal("concurrent transitions produced no state change")
	}
}

func TestRuntimeClosesResourceThroughStatelessWrapper(t *testing.T) {
	resource := new(testResourceDialer)
	wrapped := ComposeDialer(testDialer{}, resource)
	runtime := NewRuntime(wrapped)
	if runtime.Session != nil {
		t.Fatal("resource-only runtime exposed a session")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestSessionGroupConnectUpdatesSnapshotBeforeReturn(t *testing.T) {
	group := NewSessionGroup(newTestSession(), newTestSession())
	defer group.Close()
	if err := group.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := group.Snapshot().State; state != SessionConnected {
		t.Fatalf("state after Connect = %s, want connected", state)
	}
}

func TestSessionGroupUpdatesCauseWithoutAggregateStateChange(t *testing.T) {
	firstErr := errors.New("first disconnected")
	secondErr := errors.New("second disconnected")
	first := newTestSession()
	first.state.Transition(SessionConnecting, nil)
	first.state.Transition(SessionDisconnected, firstErr)
	second := newTestSession()
	second.state.Transition(SessionConnecting, nil)
	second.state.Transition(SessionDisconnected, secondErr)
	group := NewSessionGroup(first, second)
	defer group.Close()
	if cause := group.Snapshot().Cause; !errors.Is(cause, firstErr) {
		t.Fatalf("initial cause = %v, want %v", cause, firstErr)
	}

	first.state.Transition(SessionConnecting, nil)
	deadline := time.Now().Add(time.Second)
	for !errors.Is(group.Snapshot().Cause, secondErr) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshot := group.Snapshot(); snapshot.State != SessionDisconnected || !errors.Is(snapshot.Cause, secondErr) {
		t.Fatalf("updated snapshot = %+v, want disconnected with second cause", snapshot)
	}
}

func TestSessionGroupCloseWaitsForConcurrentCloseAndReturnsError(t *testing.T) {
	wantErr := errors.New("close failed")
	child := &blockingCloseSession{
		testSession: newTestSession(),
		started:     make(chan struct{}),
		release:     make(chan struct{}),
		err:         wantErr,
	}
	group := NewSessionGroup(child)
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- group.Close() }()
	<-child.started
	go func() { second <- group.Close() }()
	select {
	case err := <-second:
		t.Fatalf("concurrent Close returned before cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(child.release)
	if err := <-first; !errors.Is(err, wantErr) {
		t.Fatalf("first Close error = %v, want %v", err, wantErr)
	}
	if err := <-second; !errors.Is(err, wantErr) {
		t.Fatalf("second Close error = %v, want %v", err, wantErr)
	}
}

func TestSessionGroupConnectCannotSucceedAfterClose(t *testing.T) {
	child := &blockingConnectSession{
		testSession: newTestSession(),
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	group := NewSessionGroup(child)
	connected := make(chan error, 1)
	go func() { connected <- group.Connect(context.Background()) }()
	<-child.started
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	close(child.release)
	if err := <-connected; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Connect error = %v, want net.ErrClosed", err)
	}
}

func TestComposeRuntimePreservesSeparateParentSession(t *testing.T) {
	parentSession := newTestSession()
	parent := NewRuntime(WithSession(testDialer{}, parentSession))
	child := testDialer{}
	runtime := ComposeRuntime(child, parent)
	if runtime.Session == nil || runtime.Session.Snapshot() != parentSession.Snapshot() {
		t.Fatal("composed runtime lost the parent session")
	}
	if _, ok := runtime.Dialer.(Session); ok {
		t.Fatal("stateless child dialer acquired session methods")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if state := parentSession.Snapshot().State; state != SessionClosed {
		t.Fatalf("parent session state after Close = %s", state)
	}
}

func TestComposeRuntimeClosesOutsideIn(t *testing.T) {
	var order []string
	parent := NewRuntime(&orderedResourceDialer{name: "parent", order: &order})
	runtime := ComposeRuntime(&orderedResourceDialer{name: "child", order: &order}, parent)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "child" || order[1] != "parent" {
		t.Fatalf("close order = %v, want [child parent]", order)
	}
}

func TestRuntimeDialerHidesOwnedLifecycle(t *testing.T) {
	runtime := NewRuntime(WithSession(testDialer{}, newTestSession()))
	if _, ok := runtime.Dialer.(Session); ok {
		t.Fatal("Runtime.Dialer exposed Session")
	}
	if _, ok := runtime.Dialer.(io.Closer); ok {
		t.Fatal("Runtime.Dialer exposed Close")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func newPacketCapableTestConn(t *testing.T) *packetCapableTestConn {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	return &packetCapableTestConn{Conn: conn}
}

func TestRuntimeDialContextHidesPacketPlane(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		name := "stateless"
		if tracked {
			name = "tracked"
		}
		t.Run(name, func(t *testing.T) {
			var owned Dialer = &streamTestDialer{conn: newPacketCapableTestConn(t)}
			if tracked {
				owned = &ownedTestDialer{Dialer: owned}
			}
			runtime := NewRuntime(owned)
			conn, err := runtime.Dialer.DialContext(context.Background(), "udp", "example.com:53")
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := conn.(net.PacketConn); ok {
				t.Fatal("DialContext exposed packet-plane methods")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeListenPacketHidesStreamPlane(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		name := "stateless"
		if tracked {
			name = "tracked"
		}
		t.Run(name, func(t *testing.T) {
			var owned Dialer = &packetTestDialer{conn: newPacketCapableTestConn(t)}
			if tracked {
				owned = &ownedTestDialer{Dialer: owned}
			}
			runtime := NewRuntime(owned)
			conn, err := runtime.Dialer.ListenPacket(context.Background(), "example.com:53")
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := conn.(net.Conn); ok {
				t.Fatal("ListenPacket exposed stream-plane methods")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeDefersCloseForStreamLease(t *testing.T) {
	resource := &ownedTestDialer{Dialer: &streamTestDialer{conn: newPacketCapableTestConn(t)}}
	runtime := NewRuntime(resource)
	conn, err := runtime.Dialer.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 0 {
		t.Fatalf("resource closed with active stream lease: %d", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestRuntimeDefersCloseForPacketLease(t *testing.T) {
	resource := &ownedTestDialer{Dialer: &packetTestDialer{conn: newPacketCapableTestConn(t)}}
	runtime := NewRuntime(resource)
	conn, err := runtime.Dialer.ListenPacket(context.Background(), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 0 {
		t.Fatalf("resource closed with active packet lease: %d", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestComposeDialerClosesOuterResourceBeforeParentSession(t *testing.T) {
	var order []string
	parentSession := &orderedSession{testSession: newTestSession(), name: "parent", order: &order}
	parent := WithSession(testDialer{}, parentSession)
	child := &orderedResourceDialer{name: "child", order: &order}
	composed := ComposeDialer(child, parent)
	session, ok := composed.(Session)
	if !ok {
		t.Fatal("composed dialer lost parent session")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "child" || order[1] != "parent" {
		t.Fatalf("close order = %v, want [child parent]", order)
	}
}

func TestComposeDialerClosesChildSessionBeforeParentResource(t *testing.T) {
	var order []string
	childSession := &orderedSession{testSession: newTestSession(), name: "child", order: &order}
	child := WithSession(testDialer{}, childSession)
	parent := &orderedResourceDialer{name: "parent", order: &order}
	composed := ComposeDialer(child, parent)
	session, ok := composed.(Session)
	if !ok {
		t.Fatal("composed dialer lost child session")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "child" || order[1] != "parent" {
		t.Fatalf("close order = %v, want [child parent]", order)
	}
}
