package shadowsocks

import (
	"net"
	"testing"

	"github.com/daeuniverse/outbound/pool"
)

func TestTCPConnReleasesBufferedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &TCPConn{
		Conn:    client,
		readBuf: pool.GetBuffer(16),
	}
	copy(conn.readBuf, "0123456789abcdef")

	buf := make([]byte, 10)
	if n, err := conn.Read(buf); err != nil || n != len(buf) {
		t.Fatalf("first Read() = %d, %v", n, err)
	}
	if conn.readBuf == nil {
		t.Fatal("partial read released its payload")
	}
	if n, err := conn.Read(buf); err != nil || n != 6 {
		t.Fatalf("second Read() = %d, %v", n, err)
	}
	if conn.readBuf != nil || conn.readOffset != 0 {
		t.Fatal("completed read retained its payload")
	}
}

func TestTCPConnCloseReleasesBufferedPayload(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &TCPConn{
		Conn:       client,
		readBuf:    pool.GetBuffer(16),
		readOffset: 4,
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if conn.readBuf != nil || conn.readOffset != 0 {
		t.Fatal("Close retained its payload")
	}
}
