package client

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"

	"github.com/samber/oops"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/outbound/protocol/hysteria2/udphop"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

const (
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type HandshakeInfo struct {
	UDPEnabled bool
	Tx         uint64 // 0 if using BBR
}

type Client struct {
	config    *Config
	lifecycle *netproxy.SingleSession[*clientResource]
}

type clientResource struct {
	pktConn net.PacketConn
	conn    quic.Connection
	udpSM   *udpSessionManager
	ctx     context.Context
	cancel  context.CancelFunc
}

func (r *clientResource) close() error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.conn != nil {
		_ = r.conn.CloseWithError(closeErrCodeProtocolError, "")
	}
	if r.pktConn != nil {
		_ = r.pktConn.Close()
	}
	return nil
}

var _ netproxy.StatefulDialer = (*Client)(nil)

func NewClient(config *Config) (*Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &Client{config: config}
	c.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*clientResource]{
		Establish: c.establish,
		IsConnected: func(resource *clientResource) bool {
			return resource.conn != nil && resource.conn.Context().Err() == nil &&
				(resource.udpSM == nil || resource.udpSM.ctx.Err() == nil)
		},
		Observe: c.observe,
		Close:   (*clientResource).close,
	})
	return c, nil
}

func (c *Client) Snapshot() netproxy.StateEvent {
	return c.lifecycle.Snapshot()
}

func (c *Client) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return c.lifecycle.WatchState(ctx)
}

func (c *Client) currentResource() (*clientResource, error) {
	return c.lifecycle.Current()
}

// openStream wraps the stream with QStream, which handles Close() properly
func (c *Client) OpenStream(ctx context.Context) (*utils.QStream, error) {
	resource, err := c.currentResource()
	if err != nil {
		return nil, err
	}
	return c.openStream(ctx, resource)
}

func (c *Client) openStream(ctx context.Context, resource *clientResource) (*utils.QStream, error) {
	stream, err := resource.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &utils.QStream{
		Stream:     stream,
		LocalAddr:  resource.conn.LocalAddr(),
		RemoteAddr: resource.conn.RemoteAddr(),
	}, nil
}

func (c *Client) DialConn(stream *utils.QStream, addr string) (net.Conn, error) {
	return c.dialConn(stream, addr)
}

func (c *Client) dialConn(stream *utils.QStream, addr string) (net.Conn, error) {
	// Send request
	err := protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		return nil, err
	}
	if c.config.FastOpen {
		// Don't wait for the response when fast open is enabled.
		// Return the connection immediately, defer the response handling
		// to the first Read() call.
		return &tcpConn{
			Orig:             stream,
			PseudoLocalAddr:  stream.LocalAddr,
			PseudoRemoteAddr: stream.RemoteAddr,
			Established:      false,
		}, nil
	}
	// Read response
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, oops.In("Hysteria2").Wrapf(err, "from remote: %v", msg)
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  stream.LocalAddr,
		PseudoRemoteAddr: stream.RemoteAddr,
		Established:      true,
	}, nil
}

func (c *Client) ListenPacket(_ context.Context, _ string) (net.PacketConn, error) {
	resource, err := c.currentResource()
	if err != nil {
		return nil, err
	}
	if resource.udpSM == nil {
		return nil, oops.In("Hysteria2").Errorf("%w: UDP not enabled", netproxy.UnsupportedTunnelTypeError)
	}
	return resource.udpSM.NewUDP()
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		resource, err := c.currentResource()
		if err != nil {
			return nil, err
		}
		stream, err := c.openStream(ctx, resource)
		if err != nil {
			return nil, err
		}
		return common.Invoke(ctx, func() (net.Conn, error) {
			return c.dialConn(stream, address)
		}, func() {
			stream.Close()
		})
	case "udp":
		conn, err := c.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{
			PacketConn: conn,
			Address:    netproxy.NewAddr("udp", address),
		}, nil
	default:
		return nil, oops.Errorf("unsupported network: %s", network)
	}
}

func (c *Client) Connect(ctx context.Context) error {
	return c.lifecycle.Connect(ctx)
}

func (c *Client) establish(ctx context.Context) (resource *clientResource, err error) {
	resourceCtx, resourceCancel := context.WithCancel(context.Background())
	resource = &clientResource{ctx: resourceCtx, cancel: resourceCancel}
	defer func(resource *clientResource) {
		if err != nil {
			_ = resource.close()
		}
	}(resource)

	if c.config.Addr.Network() == "udphop" {
		// NextDialer.ListenPacket have to get a new lAddr every time.
		// Otherwise port hopping will not work.
		initialDial := make(chan struct{})
		dialFunc := func(addr net.Addr) (net.Conn, error) {
			dialCtx := resource.ctx
			select {
			case <-initialDial:
			default:
				dialCtx = ctx
			}
			return c.config.NextDialer.DialContext(dialCtx, "udp", addr.String())
		}
		pktConn, err := udphop.NewUDPHopPacketConn(c.config.Addr.(*udphop.UDPHopAddr), c.config.UDPHopInterval, dialFunc)
		if err != nil {
			return nil, err
		}
		close(initialDial)
		resource.pktConn = pktConn
	} else {
		pktConn, err := c.config.NextDialer.ListenPacket(ctx, c.config.Addr.String())
		if err != nil {
			return nil, err
		}
		resource.pktConn = pktConn
	}

	// Prepare Transport
	rt := &http3.Transport{
		TLSClientConfig: &c.config.TLSConfig,
		QUICConfig:      &c.config.QUICConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			qc, err := quic.DialEarly(ctx, resource.pktConn, c.config.Addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			resource.conn = qc
			return qc, nil
		},
	}
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, oops.
			In("HTTP3 handshake").
			WithContext(ctx).
			Wrapf(err, "failed to create HTTP request")
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = rt.Close()
		return nil, oops.In("HTTP3 Handshake").Wrap(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != protocol.StatusAuthOK {
		err = oops.Errorf("authentication error, HTTP status code: %v", resp.StatusCode)
		return nil, oops.In("HTTP3 Handshake").Wrap(err)
	}
	// Auth OK
	authResp := protocol.AuthResponseFromHeader(resp.Header)
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(resource.conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			congestion.UseBrutal(resource.conn, actualTx)
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(resource.conn)
		}
	}
	if authResp.UDPEnabled {
		resource.udpSM = newUDPSessionManager(resource.ctx, resource.conn)
	}
	return resource, nil
}

func (c *Client) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*clientResource]) {
	resource := handle.Resource()
	var udpDone <-chan struct{}
	if resource.udpSM != nil {
		udpDone = resource.udpSM.ctx.Done()
	}
	select {
	case <-ctx.Done():
		return
	case <-resource.conn.Context().Done():
	case <-udpDone:
	}
	cause := resource.conn.Context().Err()
	if cause == nil {
		cause = net.ErrClosed
	}
	handle.Disconnect(cause)
}

func (c *Client) Close() error {
	return c.lifecycle.Close()
}
