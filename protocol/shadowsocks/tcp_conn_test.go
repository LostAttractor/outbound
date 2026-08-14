package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/socks5"
)

type interruptingCloseConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func (c *interruptingCloseConn) Read([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.readStarted) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *interruptingCloseConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *interruptingCloseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *interruptingCloseConn) LocalAddr() net.Addr         { return nil }
func (c *interruptingCloseConn) RemoteAddr() net.Addr        { return nil }
func (c *interruptingCloseConn) SetDeadline(time.Time) error { return nil }
func (c *interruptingCloseConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *interruptingCloseConn) SetWriteDeadline(time.Time) error {
	return nil
}

type shortWriteConn struct {
	bytes.Buffer
	writes int
}

func (c *shortWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *shortWriteConn) Close() error                     { return nil }
func (c *shortWriteConn) LocalAddr() net.Addr              { return nil }
func (c *shortWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *shortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortWriteConn) SetWriteDeadline(time.Time) error { return nil }
func (c *shortWriteConn) Write(b []byte) (int, error) {
	c.writes++
	n := len(b) / 2
	c.Buffer.Write(b[:n])
	return n, nil
}

type fullWriteErrorConn struct {
	shortWriteConn
	err error
}

func (c *fullWriteErrorConn) Write(b []byte) (int, error) {
	c.writes++
	c.Buffer.Write(b)
	err := c.err
	c.err = nil
	return len(b), err
}

type fixedSaltGenerator struct {
	salt []byte
}

func (g *fixedSaltGenerator) Get() []byte {
	salt := pool.GetBuffer(len(g.salt))
	copy(salt, g.salt)
	return salt
}
func (g *fixedSaltGenerator) Close() error { return nil }

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

func TestTCPConnCloseUnblocksRead(t *testing.T) {
	underlay := &interruptingCloseConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
	conn := &TCPConn{
		Conn:       underlay,
		cipherConf: &ciphers.CipherConf{SaltLen: 1},
	}
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_, _ = conn.Read(make([]byte, 1))
	}()
	<-underlay.readStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func TestTCPConnWriteRejectsShortUnderlayWrite(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	underlay := &shortWriteConn{}
	conn := &TCPConn{
		Conn:        underlay,
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
		onceWrite:   true,
	}

	if n, err := conn.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
	if n, err := conn.Write([]byte("retry")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("second Write() = %d, %v; want 0, %v", n, err, io.ErrShortWrite)
	}
	if underlay.writes != 1 {
		t.Fatalf("underlay writes = %d, want 1", underlay.writes)
	}
}

func TestTCPConnWriteKeepsAlignedStreamUsableAfterFullWriteError(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := errors.New("write failed after consuming buffer")
	underlay := &fullWriteErrorConn{err: writeErr}
	conn := &TCPConn{
		Conn:        underlay,
		cipherWrite: aead,
		nonceWrite:  make([]byte, aead.NonceSize()),
		onceWrite:   true,
	}
	payload := []byte("payload")

	if n, err := conn.Write(payload); n != len(payload) || !errors.Is(err, writeErr) {
		t.Fatalf("Write() = %d, %v; want %d, %v", n, err, len(payload), writeErr)
	}
	retry := []byte("retry")
	if n, err := conn.Write(retry); n != len(retry) || err != nil {
		t.Fatalf("second Write() = %d, %v; want %d, nil", n, err, len(retry))
	}
	if underlay.writes != 2 {
		t.Fatalf("underlay writes = %d, want 2", underlay.writes)
	}
}

func TestTCPConnWriteRejectsInvalidAddressBeforeWriting(t *testing.T) {
	underlay := &shortWriteConn{}
	conn := &TCPConn{
		Conn:       underlay,
		addr:       &socks5.AddressInfo{Type: socks5.AddressTypeDomain, Hostname: strings.Repeat("x", 256)},
		cipherConf: ciphers.AeadCiphersConf["aes-128-gcm"],
		masterKey:  make([]byte, 16),
		sg:         &fixedSaltGenerator{salt: make([]byte, 16)},
		nonceWrite: make([]byte, 12),
	}

	if n, err := conn.Write([]byte("payload")); n != 0 || err == nil {
		t.Fatalf("Write() = %d, %v; want address error", n, err)
	}
	if underlay.writes != 0 {
		t.Fatalf("underlay writes = %d, want 0", underlay.writes)
	}
	if conn.onceWrite {
		t.Fatal("failed address encoding marked the first write complete")
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
