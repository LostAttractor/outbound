package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/net/http2"
)

type Conn struct {
	nextDialer netproxy.Dialer
	ctx        context.Context
	cancel     context.CancelFunc
	muConn     sync.RWMutex
	conn       net.Conn
	closeOnce  sync.Once
	closeErr   error

	proxy        *HttpProxy
	magicNetwork string
	tgt          string

	ctxShakeFinished    context.Context
	cancelShakeFinished func()
	muShake             sync.Mutex
	muFinishShakeFuncs  sync.Mutex
	finishShakeFuncs    []func(conn net.Conn)

	isH2 bool
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.setDeadline(t, net.Conn.SetDeadline)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.setDeadline(t, net.Conn.SetReadDeadline)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadline(t, net.Conn.SetWriteDeadline)
}

func (c *Conn) setDeadline(t time.Time, set func(net.Conn, time.Time) error) error {
	c.muFinishShakeFuncs.Lock()
	defer c.muFinishShakeFuncs.Unlock()
	select {
	case <-c.ctxShakeFinished.Done():
		conn, isH2 := c.currentConn()
		if conn == nil {
			return io.EOF
		}
		if isH2 {
			return nil
		}
		return set(conn, t)
	default:
		c.finishShakeFuncs = append(c.finishShakeFuncs, func(conn net.Conn) {
			if !c.isH2 {
				_ = set(conn, t)
			}
		})
		return nil
	}
}

func NewConn(nextDialer netproxy.Dialer, proxy *HttpProxy, addr string, network string) *Conn {
	ctxShakeFinished, cancelShakeFinished := context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{
		nextDialer:          nextDialer,
		ctx:                 ctx,
		cancel:              cancel,
		proxy:               proxy,
		tgt:                 addr,
		magicNetwork:        network,
		ctxShakeFinished:    ctxShakeFinished,
		cancelShakeFinished: cancelShakeFinished,
	}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.muShake.Lock()
	defer c.muShake.Unlock()
	defer func() {
		if err == nil {
			c.muFinishShakeFuncs.Lock()
			defer c.muFinishShakeFuncs.Unlock()
			// SetDeadline after c.conn filled.
			for _, f := range c.finishShakeFuncs {
				f(c.conn)
			}
		}
	}()
	select {
	case <-c.ctxShakeFinished.Done():
		conn, _ := c.currentConn()
		if conn == nil {
			return 0, io.EOF
		}
		return conn.Write(b)
	default:
		// Handshake
		defer c.cancelShakeFinished()
		_, firstLine, _ := bufio.ScanLines(b, true)
		isHttpReq := regexp.MustCompile(`^\S+ \S+ HTTP/[\d.]+$`).Match(firstLine)

		var req *http.Request
		if isHttpReq && !c.proxy.https {
			// HTTP Request

			req, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(b)))
			if err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					// Request more data.
					return len(b), nil
				}
				// Error
				return 0, err
			}

			req.URL.Scheme = "http"
			req.URL.Host = c.tgt
		} else {
			// Arbitrary TCP

			// HACK. http.ReadRequest also does this.
			reqURL, err := url.Parse("http://" + c.tgt)
			if err != nil {
				return 0, err
			}
			method := "CONNECT"
			if !c.proxy.transport {
				reqURL.Scheme = ""
			} else {
				method = "PUT"
			}

			req, err = http.NewRequest(method, reqURL.String(), nil)
			if err != nil {
				return 0, err
			}
		}
		if c.proxy.Host != "" {
			req.Host = c.proxy.Host
		} else if c.proxy.transport {
			req.Host = "www.example.com"
		}
		if c.proxy.transport {
			req.URL.Path = c.proxy.Path
		}
		req.Close = false
		if c.proxy.HaveAuth {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.proxy.Username+":"+c.proxy.Password)))
		}
		req = req.WithContext(c.ctx)
		// https://www.rfc-editor.org/rfc/rfc7230#appendix-A.1.2
		// As a result, clients are encouraged not to send the Proxy-Connection header field in any requests.
		if len(req.Header.Values("Proxy-Connection")) > 0 {
			req.Header.Del("Proxy-Connection")
		}

		connectHttp1 := func(rawConn net.Conn) (n int, err error) {
			stopClose := context.AfterFunc(c.ctx, func() { _ = rawConn.Close() })
			defer stopClose()
			defer func() {
				if err != nil {
					_ = rawConn.Close()
				}
			}()
			err = req.WriteProxy(rawConn)
			if err != nil {
				return 0, err
			}

			if isHttpReq {
				// Allow read here to void race.
				return len(b), nil
			} else {
				// We should read tcp connection here, and we will be guaranteed higher priority by chShakeFinished.
				resp, err := http.ReadResponse(bufio.NewReader(rawConn), req)
				if err != nil {
					if resp != nil {
						resp.Body.Close()
					}
					return 0, err
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					err = fmt.Errorf("connect server using proxy error, StatusCode [%d]", resp.StatusCode)
					return 0, err
				}
				return rawConn.Write(b)
			}
		}

		// Thanks to v2fly/v2ray-core.
		connectHttp2 := func(rawConn net.Conn, h2clientConn *http2.ClientConn, req *http.Request) (conn *http2Conn, n int, err error) {
			pr, pw := io.Pipe()
			req.Body = pr

			var pErr error
			var done = make(chan struct{}, 1)

			go func() {
				_, pErr = pw.Write(b)
				done <- struct{}{}
			}()

			resp, err := h2clientConn.RoundTrip(req) // nolint: bodyclose
			if err != nil {
				_ = pw.CloseWithError(err)
				_ = pr.CloseWithError(err)
				return nil, 0, err
			}

			select {
			case <-done:
			case <-c.ctx.Done():
				_ = resp.Body.Close()
				return nil, 0, c.ctx.Err()
			}
			if pErr != nil {
				_ = resp.Body.Close()
				return nil, 0, pErr
			}

			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				return nil, 0, fmt.Errorf("proxy responded with non 200 code: %v", resp.Status)
			}
			return newHTTP2Conn(rawConn, pw, resp.Body), len(b), nil
		}

		if !c.proxy.https {
			ctx, cancel := netproxy.NewDialTimeoutContextFrom(c.ctx)
			defer cancel()
			conn, err := c.nextDialer.DialContext(ctx, c.magicNetwork, c.proxy.Addr)
			if err != nil {
				return 0, err
			}
			if !c.installConn(conn, false) {
				return 0, net.ErrClosed
			}
			return connectHttp1(conn)
		}

		rawConn, h2Conn, err := c.proxy.pool.getConn(c.ctx, false)
		if err != nil {
			return 0, err
		}
		if h2Conn != nil {
			proxyConn, n, err := connectHttp2(rawConn, h2Conn, req)
			if err != nil {
				return 0, err
			}
			if !c.installConn(proxyConn, true) {
				return 0, net.ErrClosed
			}
			return n, nil
		} else {
			if !c.installConn(rawConn, false) {
				return 0, net.ErrClosed
			}
			return connectHttp1(rawConn)
		}
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	<-c.ctxShakeFinished.Done()
	conn, _ := c.currentConn()
	if conn == nil {
		return 0, io.EOF
	}
	return conn.Read(b)
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.muConn.Lock()
		conn := c.conn
		c.muConn.Unlock()
		if conn != nil {
			c.closeErr = conn.Close()
		}
		c.cancelShakeFinished()
		c.muShake.Lock()
		c.muShake.Unlock()
	})
	return c.closeErr
}

func (c *Conn) LocalAddr() net.Addr {
	conn, _ := c.currentConn()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	conn, _ := c.currentConn()
	if conn == nil {
		return nil
	}
	return conn.RemoteAddr()
}

func (c *Conn) installConn(conn net.Conn, isH2 bool) bool {
	c.muConn.Lock()
	if c.ctx.Err() != nil {
		c.muConn.Unlock()
		_ = conn.Close()
		return false
	}
	c.conn = conn
	c.isH2 = isH2
	c.muConn.Unlock()
	return true
}

func (c *Conn) currentConn() (net.Conn, bool) {
	c.muConn.RLock()
	defer c.muConn.RUnlock()
	return c.conn, c.isH2
}

func newHTTP2Conn(c net.Conn, pipedReqBody *io.PipeWriter, respBody io.ReadCloser) *http2Conn {
	return &http2Conn{Conn: c, in: pipedReqBody, out: respBody}
}

type http2Conn struct {
	net.Conn
	in  *io.PipeWriter
	out io.ReadCloser
}

func (h *http2Conn) Read(p []byte) (n int, err error) {
	return h.out.Read(p)
}

func (h *http2Conn) Write(p []byte) (n int, err error) {
	return h.in.Write(p)
}

func (h *http2Conn) Close() error {
	h.in.Close()
	return h.out.Close()
}

type h2Conn struct {
	raw net.Conn
	h2  *http2.ClientConn
}

type h2ConnsPool struct {
	mu         sync.Mutex
	conns      []*h2Conn
	dialer     netproxy.Dialer
	addr       string
	ctx        context.Context
	cancel     context.CancelFunc
	operations sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
}

func newH2ConnsPool(dialer netproxy.Dialer, addr string) *h2ConnsPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &h2ConnsPool{
		dialer: dialer,
		addr:   addr,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (p *h2ConnsPool) getConn(ctx context.Context, reserve bool) (net.Conn, *http2.ClientConn, error) {
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	p.operations.Add(1)
	defer p.operations.Done()
	for _, conn := range p.conns {
		available := conn.h2.CanTakeNewRequest()
		if reserve {
			available = conn.h2.ReserveNewRequest()
		}
		if available {
			p.mu.Unlock()
			return conn.raw, conn.h2, nil
		}
	}
	p.mu.Unlock()

	dialCtx, cancel := netproxy.NewDialTimeoutContextFrom(ctx)
	stopClose := context.AfterFunc(p.ctx, cancel)
	defer stopClose()
	defer cancel()
	rawConn, err := p.dialer.DialContext(dialCtx, "tcp", p.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("h2ConnsPool.getConn: %w", err)
	}
	nextProto := ""
	if tlsConn, ok := rawConn.(*tls.Conn); ok {
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		nextProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	switch nextProto {
	case "", "http/1.1":
		if p.ctx.Err() != nil {
			_ = rawConn.Close()
			return nil, nil, net.ErrClosed
		}
		return rawConn, nil, nil
	case "h2":
		t := http2.Transport{ConnPool: p}
		h2clientConn, err := t.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		if reserve && !h2clientConn.ReserveNewRequest() {
			_ = rawConn.Close()
			return nil, nil, http2.ErrNoCachedConn
		}
		p.mu.Lock()
		if p.ctx.Err() != nil {
			p.mu.Unlock()
			_ = rawConn.Close()
			return nil, nil, net.ErrClosed
		}
		p.conns = append(p.conns, &h2Conn{raw: rawConn, h2: h2clientConn})
		p.mu.Unlock()
		return rawConn, h2clientConn, nil
	default:
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("negotiated unsupported application layer protocol: %v", nextProto)
	}
}

func (p *h2ConnsPool) GetClientConn(req *http.Request, _ string) (*http2.ClientConn, error) {
	_, h2Conn, err := p.getConn(req.Context(), true)
	return h2Conn, err
}

func (p *h2ConnsPool) MarkDead(h2c *http2.ClientConn) {
	p.mu.Lock()
	var rawConn net.Conn
	for i, conn := range p.conns {
		if conn.h2 == h2c {
			rawConn = conn.raw
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
	if rawConn != nil {
		_ = rawConn.Close()
	}
}

func (p *h2ConnsPool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.cancel()
		p.mu.Unlock()
		p.operations.Wait()

		p.mu.Lock()
		conns := make([]net.Conn, len(p.conns))
		for i, conn := range p.conns {
			conns[i] = conn.raw
		}
		p.conns = nil
		p.mu.Unlock()

		for _, conn := range conns {
			p.closeErr = errors.Join(p.closeErr, conn.Close())
		}
	})
	return p.closeErr
}
