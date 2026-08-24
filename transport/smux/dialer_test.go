package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type pipeDialer struct {
	server chan net.Conn
}

func (d *pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	d.server <- server
	return client, nil
}
func (d *pipeDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected ListenPacket")
}

type udpPassthroughDialer struct {
	dialNetwork   string
	dialAddress   string
	listenAddress string
}

var (
	errDialUDP   = errors.New("dial UDP")
	errListenUDP = errors.New("listen UDP")
)

func (d *udpPassthroughDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.dialNetwork = network
	d.dialAddress = address
	return nil, errDialUDP
}

func (d *udpPassthroughDialer) ListenPacket(_ context.Context, address string) (net.PacketConn, error) {
	d.listenAddress = address
	return nil, errListenUDP
}

func TestUDPPassthroughUsesParentDialer(t *testing.T) {
	parent := new(udpPassthroughDialer)
	dialer := &Smux{Dialer: parent, PassthroughUdp: true}

	if _, err := dialer.DialContext(context.Background(), "udp", "dns.example:53"); !errors.Is(err, errDialUDP) {
		t.Fatalf("DialContext error = %v, want %v", err, errDialUDP)
	}
	if parent.dialNetwork != "udp" || parent.dialAddress != "dns.example:53" {
		t.Fatalf("parent DialContext called with %q, %q", parent.dialNetwork, parent.dialAddress)
	}

	if _, err := dialer.ListenPacket(context.Background(), "0.0.0.0:0"); !errors.Is(err, errListenUDP) {
		t.Fatalf("ListenPacket error = %v, want %v", err, errListenUDP)
	}
	if parent.listenAddress != "0.0.0.0:0" {
		t.Fatalf("parent ListenPacket called with %q", parent.listenAddress)
	}
}

func TestUnderlyingDisconnectPublishesState(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn, 1)}
	dialer := &Smux{Dialer: parent}
	accept := func() <-chan net.Conn {
		serverReady := make(chan net.Conn, 1)
		go func() {
			server := <-parent.server
			if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
				_ = server.Close()
				return
			}
			serverReady <- server
		}()
		return serverReady
	}
	serverReady := accept()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := <-serverReady
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("state after Connect = %s", state)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.Snapshot().State != netproxy.SessionDisconnected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionDisconnected {
		t.Fatalf("state after underlay close = %s, want disconnected", state)
	}

	serverReady = accept()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server = <-serverReady
	if state := dialer.Snapshot().State; state != netproxy.SessionConnected {
		t.Fatalf("state after reconnect = %s, want connected", state)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolErrorPublishesState(t *testing.T) {
	parent := &pipeDialer{server: make(chan net.Conn, 1)}
	dialer := &Smux{Dialer: parent}
	serverReady := make(chan net.Conn, 1)
	go func() {
		server := <-parent.server
		if _, err := io.ReadFull(server, make([]byte, 2)); err != nil {
			_ = server.Close()
			return
		}
		serverReady <- server
	}()
	if err := dialer.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := <-serverReady
	defer server.Close()
	if _, err := server.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for dialer.Snapshot().State != netproxy.SessionDisconnected && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if state := dialer.Snapshot().State; state != netproxy.SessionDisconnected {
		t.Fatalf("state after protocol error = %s, want disconnected", state)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
}
