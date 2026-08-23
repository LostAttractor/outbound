package http

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type blockingWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

type blockingDialer struct {
	started chan struct{}
	release chan struct{}
	peer    net.Conn
}

func (d *blockingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	close(d.started)
	<-d.release
	conn, peer := net.Pipe()
	d.peer = peer
	return conn, nil
}

func (d *blockingDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestConnCloseUnblocksEstablishedWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	underlay := &blockingWriteConn{Conn: client, started: make(chan struct{})}
	conn := NewConn(nil, nil, "", "")
	if !conn.installConn(underlay, false) {
		t.Fatal("failed to install test underlay")
	}
	conn.cancelShakeFinished()

	written := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("blocked"))
		written <- err
	}()
	<-underlay.started

	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind Write")
	}
	select {
	case <-written:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Write")
	}
}

func TestConnCloseWaitsForLateDialCleanup(t *testing.T) {
	dialer := &blockingDialer{started: make(chan struct{}), release: make(chan struct{})}
	conn := NewConn(dialer, &HttpProxy{Addr: "proxy.example:80"}, "target.example:443", "tcp")
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("payload"))
		written <- err
	}()
	<-dialer.started
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the late dial was cleaned up: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(dialer.release)
	defer func() {
		if dialer.peer != nil {
			_ = dialer.peer.Close()
		}
	}()
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := <-written; err == nil {
		t.Fatal("Write succeeded after Close")
	}
}

func TestH2PoolCloseClosesCachedConnections(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	pool := newH2ConnsPool(nil, "")
	pool.conns = append(pool.conns, &h2Conn{raw: client})
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := pool.getConn(context.Background(), false); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("GetConn after Close error = %v, want net.ErrClosed", err)
	}
	if _, err := server.Read(make([]byte, 1)); err == nil {
		t.Fatal("cached connection remained open")
	}
}

func TestH2PoolCloseWaitsForAdmittedDial(t *testing.T) {
	dialer := &blockingDialer{started: make(chan struct{}), release: make(chan struct{})}
	pool := newH2ConnsPool(dialer, "proxy.example:443")
	result := make(chan error, 1)
	go func() {
		_, _, err := pool.getConn(context.Background(), false)
		result <- err
	}()
	<-dialer.started
	closed := make(chan error, 1)
	go func() { closed <- pool.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before admitted dial: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(dialer.release)
	defer func() {
		if dialer.peer != nil {
			_ = dialer.peer.Close()
		}
	}()
	if err := <-result; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("GetConn error = %v, want net.ErrClosed", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}
