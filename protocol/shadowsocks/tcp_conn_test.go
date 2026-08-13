package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/common"
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

func TestTCPConnSealWritesValidChunks(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	conn := &TCPConn{
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
	}
	payload := bytes.Repeat([]byte("x"), TCPChunkMaxLen+17)
	var sealed bytes.Buffer
	conn.seal(&sealed, payload)

	nonce := make([]byte, aead.NonceSize())
	var plaintext []byte
	for sealed.Len() > 0 {
		lengthCiphertext := sealed.Next(2 + aead.Overhead())
		lengthBytes, err := aead.Open(nil, nonce, lengthCiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		common.BytesIncLittleEndian(nonce)
		chunkLength := int(binary.BigEndian.Uint16(lengthBytes))
		chunkCiphertext := sealed.Next(chunkLength + aead.Overhead())
		chunk, err := aead.Open(nil, nonce, chunkCiphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		common.BytesIncLittleEndian(nonce)
		plaintext = append(plaintext, chunk...)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatal("decrypted chunks do not match payload")
	}
}
