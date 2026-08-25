package netproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
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

type blockingResourceDialer struct {
	testDialer
	started chan struct{}
	release chan struct{}
	err     error
}

type packetCapableTestConn struct{ net.Conn }

func (c *packetCapableTestConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}

func (c *packetCapableTestConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("not implemented")
}

func (c *packetCapableTestConn) SyscallConn() (syscall.RawConn, error) {
	return nil, nil
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

func (d *blockingResourceDialer) Close() error {
	close(d.started)
	<-d.release
	return d.err
}

func retireRuntime(t *testing.T, runtime *Runtime) {
	t.Helper()
	runtime.Retire()
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	if _, ok := runtime.Session(); ok {
		t.Fatal("resource-only runtime exposed a session")
	}
	retireRuntime(t, runtime)
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestRuntimeRetireDoesNotWaitForCleanup(t *testing.T) {
	wantErr := errors.New("cleanup failed")
	resource := &blockingResourceDialer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		err:     wantErr,
	}
	runtime := NewRuntime(resource)
	retired := make(chan struct{})
	go func() {
		runtime.Retire()
		close(retired)
	}()
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("Retire blocked on resource cleanup")
	}
	select {
	case <-resource.started:
	case <-time.After(time.Second):
		t.Fatal("resource cleanup did not start")
	}
	waitCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Wait(waitCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait during cleanup error = %v, want context.Canceled", err)
	}
	close(resource.release)
	if err := runtime.Wait(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Wait error = %v, want %v", err, wantErr)
	}
	if err := runtime.Wait(waitCtx); !errors.Is(err, wantErr) {
		t.Fatalf("completed Wait with canceled context = %v, want %v", err, wantErr)
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

func TestRuntimeRetireWaitsForConnect(t *testing.T) {
	owner := &blockingConnectSession{
		testSession: newTestSession(),
		started:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	runtime := NewRuntime(WithSession(testDialer{}, owner))
	session, ok := runtime.Session()
	if !ok {
		t.Fatal("Runtime lost Session")
	}
	connected := make(chan error, 1)
	go func() { connected <- session.Connect(context.Background()) }()
	<-owner.started
	runtime.Retire()
	if state := owner.Snapshot().State; state == SessionClosed {
		t.Fatal("Runtime closed its Session during Connect")
	}
	close(owner.release)
	if err := <-connected; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Connect error = %v, want net.ErrClosed", err)
	}
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state := owner.Snapshot().State; state != SessionClosed {
		t.Fatalf("Session state after drain = %s, want closed", state)
	}
}

func TestRuntimePreservesComposedParentSession(t *testing.T) {
	parentSession := newTestSession()
	parent := WithSession(testDialer{}, parentSession)
	child := testDialer{}
	runtime := NewRuntime(ComposeDialer(child, parent))
	session, ok := runtime.Session()
	if !ok || session.Snapshot() != parentSession.Snapshot() {
		t.Fatal("composed runtime lost the parent session")
	}
	if _, ok := runtime.Dialer().(Session); ok {
		t.Fatal("stateless child dialer acquired session methods")
	}
	retireRuntime(t, runtime)
	if state := parentSession.Snapshot().State; state != SessionClosed {
		t.Fatalf("parent session state after Close = %s", state)
	}
}

func TestRuntimeDialerHidesOwnedLifecycle(t *testing.T) {
	runtime := NewRuntime(WithSession(testDialer{}, newTestSession()))
	if _, ok := runtime.Dialer().(Session); ok {
		t.Fatal("Runtime.Dialer exposed Session")
	}
	if _, ok := runtime.Dialer().(io.Closer); ok {
		t.Fatal("Runtime.Dialer exposed Close")
	}
	if session, ok := runtime.Session(); !ok {
		t.Fatal("Runtime lost Session")
	} else if _, ok := session.(io.Closer); ok {
		t.Fatal("Runtime.Session exposed Close")
	}
	retireRuntime(t, runtime)
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
	runtime := NewRuntime(&streamTestDialer{conn: newPacketCapableTestConn(t)})
	conn, err := runtime.Dialer().DialContext(context.Background(), "udp", "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(net.PacketConn); ok {
		t.Fatal("DialContext exposed packet-plane methods")
	}
	if _, ok := conn.(syscall.Conn); !ok {
		t.Fatal("DialContext hid syscall.Conn")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	retireRuntime(t, runtime)
}

func TestRuntimeListenPacketHidesStreamPlane(t *testing.T) {
	runtime := NewRuntime(&packetTestDialer{conn: newPacketCapableTestConn(t)})
	conn, err := runtime.Dialer().ListenPacket(context.Background(), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(net.Conn); ok {
		t.Fatal("ListenPacket exposed stream-plane methods")
	}
	if _, ok := conn.(syscall.Conn); !ok {
		t.Fatal("ListenPacket hid syscall.Conn")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	retireRuntime(t, runtime)
}

func TestRuntimeDefersCloseForStreamLease(t *testing.T) {
	resource := &ownedTestDialer{Dialer: &streamTestDialer{conn: newPacketCapableTestConn(t)}}
	runtime := NewRuntime(resource)
	conn, err := runtime.Dialer().DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	runtime.Retire()
	if got := resource.closes.Load(); got != 0 {
		t.Fatalf("resource closed with active stream lease: %d", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestRuntimeDefersCloseForPacketLease(t *testing.T) {
	resource := &ownedTestDialer{Dialer: &packetTestDialer{conn: newPacketCapableTestConn(t)}}
	runtime := NewRuntime(resource)
	conn, err := runtime.Dialer().ListenPacket(context.Background(), "example.com:53")
	if err != nil {
		t.Fatal(err)
	}
	runtime.Retire()
	if got := resource.closes.Load(); got != 0 {
		t.Fatalf("resource closed with active packet lease: %d", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
}

func TestComposeDialerClosesOutsideIn(t *testing.T) {
	tests := []struct {
		name        string
		build       func(*[]string) Dialer
		wantSession bool
	}{
		{
			name: "resources",
			build: func(order *[]string) Dialer {
				return ComposeDialer(
					&orderedResourceDialer{name: "child", order: order},
					&orderedResourceDialer{name: "parent", order: order},
				)
			},
		},
		{
			name:        "resource then session",
			wantSession: true,
			build: func(order *[]string) Dialer {
				parent := WithSession(testDialer{}, &orderedSession{testSession: newTestSession(), name: "parent", order: order})
				return ComposeDialer(&orderedResourceDialer{name: "child", order: order}, parent)
			},
		},
		{
			name:        "session then resource",
			wantSession: true,
			build: func(order *[]string) Dialer {
				child := WithSession(testDialer{}, &orderedSession{testSession: newTestSession(), name: "child", order: order})
				return ComposeDialer(child, &orderedResourceDialer{name: "parent", order: order})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			composed := tt.build(&order)
			if _, ok := composed.(SessionOwner); ok != tt.wantSession {
				t.Fatalf("SessionOwner = %t, want %t", ok, tt.wantSession)
			}
			closer, ok := composed.(io.Closer)
			if !ok {
				t.Fatal("composed dialer lost resource ownership")
			}
			if err := closer.Close(); err != nil {
				t.Fatal(err)
			}
			if len(order) != 2 || order[0] != "child" || order[1] != "parent" {
				t.Fatalf("close order = %v, want [child parent]", order)
			}
		})
	}
}
