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
