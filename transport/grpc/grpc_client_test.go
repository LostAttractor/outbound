package grpc

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type blockingDialer struct {
	once    sync.Once
	started chan struct{}
}

func (d *blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *blockingDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

func TestCloseCancelsConnect(t *testing.T) {
	parent := &blockingDialer{started: make(chan struct{})}
	dialer := &Dialer{
		StatelessDialer: protocol.StatelessDialer{ParentDialer: parent},
		Address:         "proxy.example:443",
		ServerName:      "proxy.example",
		AllowInsecure:   true,
	}
	result := make(chan error, 1)
	go func() { result <- dialer.Connect(context.Background()) }()
	select {
	case <-parent.started:
	case <-time.After(time.Second):
		t.Fatal("Connect did not reach the parent dialer")
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("Connect succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel Connect")
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionClosed {
		t.Fatalf("state = %s, want closed", state)
	}
}
