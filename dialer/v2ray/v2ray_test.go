package v2ray

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	protocolhttp "github.com/daeuniverse/outbound/protocol/http"
	transporttls "github.com/daeuniverse/outbound/transport/tls"
	"github.com/daeuniverse/outbound/transport/ws"
)

type testParentDialer struct {
	closeCalls int
}

func (*testParentDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (*testParentDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func (d *testParentDialer) Close() error {
	d.closeCalls++
	return nil
}

type testProtocolDialer struct{}

func (testProtocolDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}

func (testProtocolDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func setProtocolCreator(t *testing.T, name string, creator protocol.Creator) {
	t.Helper()
	previous, existed := protocol.Mapper[name]
	protocol.Mapper[name] = creator
	t.Cleanup(func() {
		if existed {
			protocol.Mapper[name] = previous
		} else {
			delete(protocol.Mapper, name)
		}
	})
}

func TestV2RayTransportBuildersPreserveParent(t *testing.T) {
	parent := new(testParentDialer)
	var transport netproxy.Dialer
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Dialer, error) {
		transport = next
		return testProtocolDialer{}, nil
	})

	const websocketLink = "vless://00000000-0000-0000-0000-000000000000@proxy.example:443?type=ws&security=tls&host=cdn.example&sni=tls.example&path=%2Fws#node"
	websocketBuilder, property, err := NewV2Ray(websocketLink)
	if err != nil {
		t.Fatal(err)
	}
	if property.Name != "node" || property.Address != "proxy.example:443" || property.Protocol != "vless" {
		t.Fatalf("property = %#v", property)
	}

	tests := []struct {
		name    string
		builder dialer.Dialer
		check   func(*testing.T, netproxy.Dialer)
	}{
		{
			name:    "websocket",
			builder: websocketBuilder,
			check: func(t *testing.T, transport netproxy.Dialer) {
				t.Helper()
				got, ok := transport.(*ws.Ws)
				if !ok || got.ParentDialer != parent {
					t.Fatalf("transport = %#v, want websocket with supplied parent", transport)
				}
			},
		},
		{
			name: "tls",
			builder: &V2Ray{
				Add: "proxy.example", Port: "443", ID: "id", Net: "tcp", Type: "none", TLS: "tls", SNI: "tls.example", Protocol: "vless",
			},
			check: func(t *testing.T, transport netproxy.Dialer) {
				t.Helper()
				got, ok := transport.(*transporttls.Tls)
				if !ok || got.ParentDialer != parent {
					t.Fatalf("transport = %#v, want TLS with supplied parent", transport)
				}
			},
		},
		{
			name: "http",
			builder: &V2Ray{
				Add: "proxy.example", Port: "80", ID: "id", Net: "h2", Path: "/tunnel", Protocol: "vless",
			},
			check: func(t *testing.T, transport netproxy.Dialer) {
				t.Helper()
				got, ok := transport.(*protocolhttp.HttpProxy)
				if !ok || got.ParentDialer != parent {
					t.Fatalf("transport = %#v, want HTTP with supplied parent", transport)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport = nil
			built, err := tt.builder.Dialer(&dialer.ExtraOption{TlsImplementation: "tls"}, parent)
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, transport)
			if closer, ok := built.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestV2RayClosesConstructedHTTPTransportOnProtocolError(t *testing.T) {
	wantErr := errors.New("protocol construction failed")
	parent := new(testParentDialer)
	var transport *protocolhttp.HttpProxy
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Dialer, error) {
		transport = next.(*protocolhttp.HttpProxy)
		return nil, wantErr
	})

	config := V2Ray{
		Add: "proxy.example", Port: "80", ID: "id", Net: "h2", Path: "/tunnel", Protocol: "vless",
	}
	if built, err := config.Dialer(new(dialer.ExtraOption), parent); !errors.Is(err, wantErr) || built != nil {
		t.Fatalf("Dialer() = %#v, %v; want nil, %v", built, err, wantErr)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "target.example:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HTTP transport after failed build returned %v, want net.ErrClosed", err)
	}
	if parent.closeCalls != 0 {
		t.Fatalf("parent close calls = %d, want 0", parent.closeCalls)
	}
}
