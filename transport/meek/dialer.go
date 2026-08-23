package meek

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
)

type Dialer struct {
	nextDialer netproxy.Dialer
	url        string
	transport  *http.Transport
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	workers    sync.WaitGroup
	closeOnce  sync.Once
}

var _ netproxy.Dialer = (*Dialer)(nil)

func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}

	m := &Dialer{nextDialer: d}

	query := u.Query()
	m.url = query.Get("url")
	if m.url == "" {
		return nil, fmt.Errorf("NewMeek: url is empty")
	}

	meekUrl, err := url.Parse(m.url)
	if err != nil {
		return nil, fmt.Errorf("NewMeek: %w", err)
	}
	if meekUrl.Scheme != "https" {
		return nil, fmt.Errorf("NewMeek: unimplemented backdrop")
	}

	skipVerify := query.Get("allowInsecure") == "true" || query.Get("allowInsecure") == "1" ||
		query.Get("skipVerify") == "true" || query.Get("skipVerify") == "1"
	alpn := []string{"h2", "http/1.1"}
	if query.Get("alpn") != "" {
		alpn = strings.Split(query.Get("alpn"), ",")
	}
	serverName := query.Get("serverName")
	if serverName == "" {
		serverName = meekUrl.Hostname()
	}
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: skipVerify,
		NextProtos:         alpn,
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := m.nextDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("[Meek]: dial to %s: %w", addr, err)
			}
			return conn, nil
		},
		TLSClientConfig: tlsConfig,
	}

	return m, nil
}

func (m *Dialer) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch network {
	case "tcp":
		tripper := &httpTripperClient{
			url:          m.url,
			roundTripper: m.transport,
		}

		clientConfig := &config{
			MaxWriteSize:             65536,
			WaitSubsequentWriteMs:    10,
			InitialPollingIntervalMs: 100,
			MaxPollingIntervalMs:     1000,
			MinPollingIntervalMs:     10,
			BackoffFactor:            1.5,
			FailedRetryIntervalMs:    1000,
		}

		session, err := newClientSession(m.ctx, tripper, clientConfig, &m.workers)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			_ = session.Close()
			return nil, err
		}
		return session, nil
	case "udp":
		return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (m *Dialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: meek+udp", netproxy.UnsupportedTunnelTypeError)
}

func (m *Dialer) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.cancel()
		m.mu.Unlock()
		m.workers.Wait()
		m.transport.CloseIdleConnections()
	})
	return nil
}
