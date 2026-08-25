package dialer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type ExtraOption struct {
	AllowInsecure       bool
	TlsImplementation   string
	TlsFragment         bool
	TlsFragmentLength   string
	TlsFragmentInterval string
	UtlsImitate         string
	BandwidthMaxTx      string
	BandwidthMaxRx      string
	UDPHopInterval      time.Duration
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}

type Dialer interface {
	Dialer(option *ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error)
}

type dataPlane struct{ dialer netproxy.Dialer }

type streamView struct{ net.Conn }

type packetView struct{ net.PacketConn }

type syscallStreamView struct {
	*streamView
	raw syscall.Conn
}

func (c *syscallStreamView) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

type closeWriteSyscallStreamView struct {
	*syscallStreamView
	closeWriter netproxy.CloseWriter
}

func (c *closeWriteSyscallStreamView) CloseWrite() error {
	return c.closeWriter.CloseWrite()
}

type syscallPacketView struct {
	*packetView
	raw syscall.Conn
}

func (c *syscallPacketView) SyscallConn() (syscall.RawConn, error) {
	return c.raw.SyscallConn()
}

func (d *dataPlane) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	view := &streamView{Conn: conn}
	closeWriter, hasCloseWriter := conn.(netproxy.CloseWriter)
	raw, hasSyscallConn := conn.(syscall.Conn)
	if hasSyscallConn {
		withSyscall := &syscallStreamView{streamView: view, raw: raw}
		if hasCloseWriter {
			return &closeWriteSyscallStreamView{syscallStreamView: withSyscall, closeWriter: closeWriter}, nil
		}
		return withSyscall, nil
	}
	if hasCloseWriter {
		return &netproxy.CloseWriteConn{Conn: view, CloseWriter: closeWriter}, nil
	}
	return view, nil
}

func (d *dataPlane) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	conn, err := d.dialer.ListenPacket(ctx, address)
	if err != nil {
		return nil, err
	}
	view := &packetView{PacketConn: conn}
	if raw, ok := conn.(syscall.Conn); ok {
		return &syscallPacketView{packetView: view, raw: raw}, nil
	}
	return view, nil
}

// BuildRuntime takes ownership of base, constructs the complete owned chain,
// and adds the single Runtime data-plane and drain boundary. On failure it
// closes both a returned partial child and the previously constructed chain.
func BuildRuntime(base netproxy.Dialer, option *ExtraOption, builders ...Dialer) (*netproxy.Runtime, error) {
	owned := base
	for _, builder := range builders {
		d, err := builder.Dialer(option, &dataPlane{dialer: owned})
		if err != nil {
			if closer, ok := d.(io.Closer); ok {
				err = errors.Join(err, closer.Close())
			}
			if closer, ok := owned.(io.Closer); ok {
				err = errors.Join(err, closer.Close())
			}
			return nil, err
		}
		owned = netproxy.ComposeDialer(d, owned)
	}
	return netproxy.NewRuntime(owned), nil
}
