package udphop

import (
	"net"
	"syscall"
	"testing"
	"time"
)

func testHopAddr() *UDPHopAddr {
	return &UDPHopAddr{
		IP:      net.IPv4(127, 0, 0, 1),
		Ports:   []uint16{443},
		PortStr: "443",
	}
}

func TestUDPHopPacketConnDoesNotExposeSyscallConn(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	conn, err := NewUDPHopPacketConn(testHopAddr(), time.Hour, func(net.Addr) (net.Conn, error) {
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, ok := conn.(syscall.Conn); ok {
		t.Fatal("UDP hop connection unexpectedly exposes SyscallConn")
	}
}
