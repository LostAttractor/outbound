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

func TestGRPCShadowsocksPreservesSession(t *testing.T) {
	d, err := (&Trojan{
		Server:      "example.com",
		Port:        443,
		Password:    "trojan-password",
		Sni:         "example.com",
		Type:        "grpc",
		ServiceName: "service",
		Encryption:  "ss;aes-128-gcm;shadowsocks-password",
	}).Dialer(new(dialer.ExtraOption), testParentDialer{})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := d.(netproxy.Session)
	if !ok {
		t.Fatal("gRPC session was hidden by the Shadowsocks wrapper")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}
