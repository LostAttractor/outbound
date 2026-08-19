package client

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestListenPacketClassifiesDisabledUDP(t *testing.T) {
	_, err := (&Client{udpDisabled: true}).ListenPacket(context.Background(), "")
	if !errors.Is(err, netproxy.UnsupportedTunnelTypeError) {
		t.Fatalf("ListenPacket error = %v, want UnsupportedTunnelTypeError", err)
	}
}

func TestListenPacketDoesNotClassifyUnconnectedClient(t *testing.T) {
	_, err := new(Client).ListenPacket(context.Background(), "")
	if errors.Is(err, netproxy.UnsupportedTunnelTypeError) {
		t.Fatalf("unconnected ListenPacket error = %v, want transient error", err)
	}
}
