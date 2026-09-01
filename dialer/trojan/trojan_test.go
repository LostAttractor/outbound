package trojan

import (
	"context"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	_ "github.com/daeuniverse/outbound/protocol/trojanc"
)

type testParentDialer struct{}

func (testParentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, nil
}

func (testParentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, nil
}

func TestGRPCShadowsocksDeclaresSessionAndOwnership(t *testing.T) {
	layer, err := (&Trojan{
		Server:      "example.com",
		Port:        443,
		Password:    "trojan-password",
		Sni:         "example.com",
		Type:        "grpc",
		ServiceName: "service",
		Encryption:  "ss;aes-128-gcm;shadowsocks-password",
	}).Build(new(dialer.ExtraOption), dialer.NewUpstream(testParentDialer{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(layer.Sessions) != 1 || len(layer.Resources) != 1 {
		t.Fatalf("layer lifecycle = %d sessions, %d resources; want 1, 1", len(layer.Sessions), len(layer.Resources))
	}
	if _, ok := layer.Data.(netproxy.Session); ok {
		t.Fatal("outer Trojan data unexpectedly exposes the inner gRPC session")
	}
	if err := layer.Close(); err != nil {
		t.Fatal(err)
	}
}
