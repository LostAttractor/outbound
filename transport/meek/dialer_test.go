package meek

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type testDialer struct{}

func (testDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}
func (testDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}

func TestDialerOwnsTransportAndSessions(t *testing.T) {
	const link = "meek://proxy.example:443?url=https%3A%2F%2Ffront.example%2Fpath&serverName=cdn.example"
	first, err := NewDialer(link, testDialer{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDialer(link, testDialer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first.transport == second.transport {
		t.Fatal("dialers shared an HTTP transport")
	}
	if first.transport.TLSClientConfig.ServerName != "cdn.example" {
		t.Fatalf("TLS server name = %q", first.transport.TLSClientConfig.ServerName)
	}

	conn, err := first.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("session read after Close error = %v, want context.Canceled", err)
	}
	if _, err := first.DialContext(context.Background(), "tcp", "target.example:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("DialContext after Close error = %v, want net.ErrClosed", err)
	}
}

type dataTripper struct {
	called  chan struct{}
	release chan struct{}
}

func (t dataTripper) RoundTrip(context.Context, Request) (Response, error) {
	select {
	case t.called <- struct{}{}:
	default:
	}
	<-t.release
	return Response{Data: []byte("data")}, nil
}

func TestSessionCloseUnblocksFullReaderQueue(t *testing.T) {
	called := make(chan struct{}, 1)
	release := make(chan struct{})
	session, err := newClientSession(context.Background(), dataTripper{called: called, release: release}, &config{
		MaxWriteSize:          1,
		FailedRetryIntervalMs: 1,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(session.readerChan); i++ {
		session.readerChan <- []byte("queued")
	}
	<-called
	close(release)
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock a full reader queue")
	}
}
