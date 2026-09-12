package direct

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

var (
	Direct netproxy.Dialer
	// Bootstrap is the physical base of proxy chains. Its DNS must not depend
	// on routing through a proxy that this very dial is trying to establish.
	Bootstrap netproxy.Dialer
)

func InitDirectDialers(mptcp bool, mark int) {
	Direct = NewDirectDialer(Option{Resolver: net.DefaultResolver, Mptcp: mptcp, Mark: mark})
	Bootstrap = NewDirectDialer(Option{Resolver: common.BootstrapResolver, Mptcp: mptcp, Mark: mark})
}

type Option struct {
	// Resolver is supplied by the owner; nil uses net.DefaultResolver.
	// Socket marks apply to data sockets. DNS transport policy belongs to Resolver.
	Resolver *net.Resolver
	Mptcp    bool
	Mark     int
}

type directDialer struct {
	dialer net.Dialer
}

func NewDirectDialer(option Option) netproxy.Dialer {
	resolver := option.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	d := &directDialer{dialer: net.Dialer{Resolver: resolver}}
	d.dialer.SetMultipathTCP(option.Mptcp)
	if option.Mark != 0 {
		d.dialer.Control = func(_, _ string, c syscall.RawConn) error {
			return netproxy.SoMarkControl(c, option.Mark)
		}
	}
	return d
}

func (d *directDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp":
		start := time.Now()
		defer func() { DirectDialLatency.Observe(time.Since(start).Seconds()) }()
	case "udp":
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *directDialer) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	config := net.ListenConfig{Control: d.dialer.Control}
	c, err := config.ListenPacket(ctx, "udp", "")
	if err != nil {
		return nil, err
	}
	return &PacketConn{
		UDPConn:  c.(*net.UDPConn),
		resolver: d.dialer.Resolver,
	}, nil
}
