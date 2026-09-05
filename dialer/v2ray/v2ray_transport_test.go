package v2ray

import (
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/grpc"
	"testing"
)

func TestGRPCSecuritySelection(t *testing.T) {
	var transport *grpc.Dialer
	setProtocolCreator(t, "vless", func(next netproxy.Dialer, _ protocol.Header) (netproxy.Layer, error) {
		transport = next.(*grpc.Dialer)
		return netproxy.Layer{Data: testProtocolDialer{}}, nil
	})
	for _, security := range []string{"none", "tls"} {
		t.Run(security, func(t *testing.T) {
			builder, _, err := NewV2Ray("vless://00000000-0000-0000-0000-000000000000@proxy.example:443?type=grpc&security=" + security + "&sni=tls.example&serviceName=custom")
			if err != nil {
				t.Fatal(err)
			}
			built, err := builder.Build(&dialer.ExtraOption{AllowInsecure: true}, dialer.NewUpstream(new(testParentDialer)))
			if err != nil {
				t.Fatal(err)
			}
			defer built.Close()
			if transport.ServiceName != "custom" || transport.Address != "proxy.example:443" {
				t.Fatalf("transport = %#v", transport)
			}
			if security == "none" {
				if transport.TLSConfig != nil {
					t.Fatal("plaintext requested but TLS enabled")
				}
			} else if transport.TLSConfig == nil || transport.TLSConfig.ServerName != "tls.example" || !transport.TLSConfig.InsecureSkipVerify {
				t.Fatalf("TLS config = %#v", transport.TLSConfig)
			}
		})
	}
}

func TestUnsupportedSecurityDoesNotFallBack(t *testing.T) {
	for _, transport := range []string{"tcp", "ws", "grpc", "h2", "meek", "httpupgrade"} {
		for _, security := range []string{"utls", "unknown", "reality"} {
			if transport == "tcp" && security == "reality" {
				continue
			}
			t.Run(transport+"/"+security, func(t *testing.T) {
				config := &V2Ray{Protocol: "vless", Add: "proxy.example", Port: "443", ID: "00000000-0000-0000-0000-000000000000", Net: transport, TLS: security}
				built, err := config.Build(new(dialer.ExtraOption), dialer.NewUpstream(new(testParentDialer)))
				if err == nil {
					built.Close()
					t.Fatal("unsupported security silently accepted")
				}
			})
		}
	}
}
