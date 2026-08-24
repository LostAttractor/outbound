package shadowsocks

import (
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/protocol/direct"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/transport/smux"
)

func TestNonSIP002MultiplexQueryIsIgnored(t *testing.T) {
	server, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@proxy.example.com:443?multiplex=1#node")
	if err != nil {
		t.Fatal(err)
	}
	built, err := server.Dialer(new(dialer.ExtraOption), direct.NewDirectDialer(direct.Option{}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := built.(*smux.Smux); ok {
		t.Fatal("non-SIP002 multiplex query enabled smux")
	}
}
