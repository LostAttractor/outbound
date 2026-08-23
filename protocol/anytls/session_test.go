package anytls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type lateWriteConn struct {
	writes       atomic.Int32
	thirdStarted chan struct{}
	releaseThird chan struct{}
}

func (c *lateWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *lateWriteConn) Close() error                     { return nil }
func (c *lateWriteConn) LocalAddr() net.Addr              { return nil }
func (c *lateWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *lateWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *lateWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lateWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *lateWriteConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 3 {
		close(c.thirdStarted)
		<-c.releaseThird
	}
	return len(p), nil
}

func TestSessionCloseWithActiveStreamDoesNotDeadlock(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	session := newSession(client, nil)
	stream := newStream(session, 1)
	session.streams[stream.id] = stream

	done := make(chan error, 1)
	go func() { done <- session.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Session.Close deadlocked with an active stream")
	}
	if !stream.closed.Load() {
		t.Fatal("Session.Close left its stream open")
	}
}

func TestFailedConnectDoesNotDisconnectAnotherSession(t *testing.T) {
	s := new(session)
	dialer := &Dialer{
		idleSessions: make(map[*session]struct{}),
		sessions:     map[*session]struct{}{s: {}},
		state:        netproxy.NewStateBroadcaster(netproxy.SessionConnected),
		ctx:          context.Background(),
	}
	wantErr := errors.New("failed attempt")
	if err := dialer.sessionError(wantErr); !errors.Is(err, wantErr) {
		t.Fatalf("sessionError = %v, want %v", err, wantErr)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("state = %s, want connected", state)
	}
}

func TestNewStreamCannotPublishAfterSessionClose(t *testing.T) {
	conn := &lateWriteConn{
		thirdStarted: make(chan struct{}),
		releaseThird: make(chan struct{}),
	}
	session := newSession(conn, nil)
	session.sendPadding = false
	result := make(chan error, 1)
	go func() {
		_, err := session.newStream("example.com:443")
		result <- err
	}()
	<-conn.thirdStarted
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	close(conn.releaseThird)
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("newStream error = %v, want net.ErrClosed", err)
	}
	if len(session.streams) != 0 {
		t.Fatalf("closed session retained %d streams", len(session.streams))
	}
}

func TestDialerCloseWaitsForAdmittedOperation(t *testing.T) {
	dialer, err := NewDialer(testParentDialer{}, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.(*Dialer)
	_, finish, err := d.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before operation cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	finish()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestDialerCloseWaitsForStreamWorker(t *testing.T) {
	dialer, err := NewDialer(testParentDialer{}, protocol.Header{})
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.(*Dialer)
	ctx, finish, err := d.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan struct{})
	release := make(chan struct{})
	aborted := make(chan struct{})
	operationDone := make(chan struct{})
	go func() {
		defer close(operationDone)
		defer finish()
		_, _ = openContext(ctx, &d.workers, func() (net.Conn, error) {
			close(opened)
			<-release
			return nil, errors.New("open failed")
		}, func() { close(aborted) })
	}()
	<-opened
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	<-aborted
	<-operationDone
	select {
	case err := <-closed:
		t.Fatalf("Close returned before worker cleanup: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

type testParentDialer struct{}

func (testParentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}
func (testParentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}
