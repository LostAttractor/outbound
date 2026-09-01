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

func setProtocolCreator(t *testing.T, name string, creator protocol.LayerCreator) {
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
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
		transport = next
		return netproxy.Layer{Data: testProtocolDialer{}}, nil
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
		builder dialer.Builder
		check   func(*testing.T, netproxy.Dialer)
	}{
		{
			name:    "websocket",
			builder: websocketBuilder,
			check: func(t *testing.T, transport netproxy.Dialer) {
				t.Helper()
				got, ok := transport.(*ws.Ws)
				if !ok {
					t.Fatalf("transport = %#v, want websocket", transport)
				}
				assertLifecycleHidden(t, got.ParentDialer)
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
				if !ok {
					t.Fatalf("transport = %#v, want TLS", transport)
				}
				assertLifecycleHidden(t, got.ParentDialer)
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
				if !ok {
					t.Fatalf("transport = %#v, want HTTP", transport)
				}
				assertLifecycleHidden(t, got.ParentDialer)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport = nil
			built, err := tt.builder.Build(&dialer.ExtraOption{TlsImplementation: "tls"}, dialer.NewUpstream(parent))
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, transport)
			if err := built.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV2RayClosesConstructedHTTPTransportOnProtocolError(t *testing.T) {
	wantErr := errors.New("protocol construction failed")
	parent := new(testParentDialer)
	var transport *protocolhttp.HttpProxy
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
		transport = next.(*protocolhttp.HttpProxy)
		return netproxy.Layer{}, wantErr
	})

	config := V2Ray{
		Add: "proxy.example", Port: "80", ID: "id", Net: "h2", Path: "/tunnel", Protocol: "vless",
	}
	if built, err := config.Build(new(dialer.ExtraOption), dialer.NewUpstream(parent)); !errors.Is(err, wantErr) || built.Data != nil {
		t.Fatalf("Build() = %#v, %v; want empty layer, %v", built, err, wantErr)
	}
	if _, err := transport.DialContext(context.Background(), "tcp", "target.example:80"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("HTTP transport after failed build returned %v, want net.ErrClosed", err)
	}
	if parent.closeCalls != 0 {
		t.Fatalf("parent close calls = %d, want 0", parent.closeCalls)
	}
}

func assertLifecycleHidden(t *testing.T, upstream netproxy.Dialer) {
	t.Helper()
	if _, ok := upstream.(dialer.Upstream); !ok {
		t.Fatalf("parent = %T, want dialer.Upstream", upstream)
	}
	if _, ok := upstream.(io.Closer); ok {
		t.Fatal("transport received parent ownership")
	}
}
