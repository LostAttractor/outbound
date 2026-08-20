package client

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestListenPacketClassifiesDisabledUDP(t *testing.T) {
	_, err := new(Client).ListenPacket(context.Background(), "")
	if !errors.Is(err, netproxy.UnsupportedTunnelTypeError) {
		t.Fatalf("ListenPacket error = %v, want UnsupportedTunnelTypeError", err)
	}
}

func TestCloseClearsUDPManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{udpSM: &udpSessionManager{ctx: ctx, cancel: cancel}}

	c.close()
	if c.udpSM != nil {
		t.Fatal("close retained stale UDP manager")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("close did not stop UDP manager")
	}
}
