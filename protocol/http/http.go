package http

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	tls2 "github.com/daeuniverse/outbound/transport/tls"
	"github.com/samber/oops"
)

// HttpProxy is an HTTP/HTTPS proxy.
type HttpProxy struct {
	protocol.StatelessDialer
	https     bool
	transport bool
	Addr      string
	Host      string
	Path      string
	HaveAuth  bool
	Username  string
	Password  string
	pool      *h2ConnsPool
}

func BuildHTTPProxy(u *url.URL, option *dialer.ExtraOption, parentDialer netproxy.Dialer) (netproxy.Layer, error) {
	query := u.Query()
	layer := netproxy.Layer{Data: parentDialer}
	https := u.Scheme == "https"
	if https {
		alpn := query.Get("alpn")
		if alpn == "" {
			alpn = "h2,http/1.1"
		}
		allowInsecure, _ := strconv.ParseBool(query.Get("allowInsecure"))
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("allow_insecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("allowinsecure"))
		}
		if !allowInsecure {
			allowInsecure, _ = strconv.ParseBool(query.Get("skipVerify"))
		}
		tlsConfig := tls2.TLSConfig{
			Host:          u.Host,
			Alpn:          alpn,
			Sni:           query.Get("sni"),
			AllowInsecure: allowInsecure,
		}
		if err := layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return netproxy.Layer{}, err
		}
	}
	path := u.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	transport, _ := strconv.ParseBool(query.Get("transport"))
	s := &HttpProxy{
		ParentDialer: layer.Data,
		https:        https,
		transport:    transport,
		Addr:         u.Host,
		Path:         path,
		Host:         query.Get("host"),
	}
	if u.User != nil {
		s.HaveAuth = true
		s.Username = u.User.Username()
		s.Password, _ = u.User.Password()
	}
	s.pool = newH2ConnsPool(s.ParentDialer, s.Addr)
	layer.Data = s
	layer.Resources = append(layer.Resources, s)
	return layer, nil
}

func (s *HttpProxy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.pool.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	switch network {
	case "tcp":
		return NewConn(s.ParentDialer, s, addr, network), nil
	default:
		return nil, oops.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *HttpProxy) ListenPacket(ctx context.Context, network string) (net.PacketConn, error) {
	return nil, oops.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
}

func (s *HttpProxy) Close() error {
	return s.pool.Close()
}
