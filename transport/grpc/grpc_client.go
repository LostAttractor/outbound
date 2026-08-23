package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/cert"
	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

type ClientConn struct {
	tun       proto.GunService_TunClient
	closer    context.CancelFunc
	muReading sync.Mutex // muReading protects reading
	muWriting sync.Mutex // muWriting protects writing
	muRecv    sync.Mutex // muReading protects recv
	muSend    sync.Mutex // muWriting protects send
	buf       []byte
	offset    int

	deadlineMu    sync.Mutex
	readDeadline  *time.Timer
	writeDeadline *time.Timer

	ctxRead     context.Context
	cancelRead  func()
	ctxWrite    context.Context
	cancelWrite func()
	ctx         context.Context
	cancel      func()
}

func NewClientConn(tun proto.GunService_TunClient, closer context.CancelFunc) *ClientConn {
	ctx, cancel := context.WithCancel(context.Background())
	ctxRead, cancelRead := context.WithCancel(context.Background())
	ctxWrite, cancelWrite := context.WithCancel(context.Background())
	return &ClientConn{
		tun:         tun,
		closer:      closer,
		ctx:         ctx,
		cancel:      cancel,
		ctxRead:     ctxRead,
		cancelRead:  cancelRead,
		ctxWrite:    ctxWrite,
		cancelWrite: cancelWrite,
	}
}

type RecvResp struct {
	hunk *proto.Hunk
	err  error
}

func (c *ClientConn) Read(p []byte) (n int, err error) {
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muReading.Lock()
	defer c.muReading.Unlock()
	if c.buf != nil {
		n = copy(p, c.buf[c.offset:])
		c.offset += n
		if c.offset == len(c.buf) {
			pool.PutBuffer(c.buf)
			c.buf = nil
		}
		return n, nil
	}
	// set 1 to avoid channel leak
	readDone := make(chan RecvResp, 1)
	// pass channel to the function to avoid closure leak
	go func(readDone chan RecvResp) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muRecv.Lock()
		defer c.muRecv.Unlock()
		recv, e := c.tun.Recv()
		readDone <- RecvResp{
			hunk: recv,
			err:  e,
		}
	}(readDone)
	select {
	case <-c.ctxRead.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case recvResp := <-readDone:
		err = recvResp.err
		if err != nil {
			if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
				err = io.EOF
			}
			return 0, err
		}
		n = copy(p, recvResp.hunk.Data)
		c.buf = pool.GetBuffer(len(recvResp.hunk.Data) - n)
		copy(c.buf, recvResp.hunk.Data[n:])
		c.offset = 0
		return n, nil
	}
}

func (c *ClientConn) Write(p []byte) (n int, err error) {
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	default:
	}

	c.muWriting.Lock()
	defer c.muWriting.Unlock()
	// set 1 to avoid channel leak
	sendDone := make(chan error, 1)
	// pass channel to the function to avoid closure leak
	go func(sendDone chan error) {
		// FIXME: not really abort the send so there is some problems when recover
		c.muSend.Lock()
		defer c.muSend.Unlock()
		e := c.tun.Send(&proto.Hunk{Data: p})
		sendDone <- e
	}(sendDone)
	select {
	case <-c.ctxWrite.Done():
		return 0, os.ErrDeadlineExceeded
	case <-c.ctx.Done():
		return 0, io.EOF
	case err = <-sendDone:
		if code := status.Code(err); code == codes.Unavailable || status.Code(err) == codes.OutOfRange {
			err = io.EOF
		}
		return len(p), err
	}
}

func (c *ClientConn) Close() error {
	select {
	case <-c.ctx.Done():
	default:
		c.cancel()
	}
	c.closer()
	return nil
}
func (c *ClientConn) CloseWrite() error {
	return c.tun.CloseSend()
}

func (c *ClientConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())

		default:
		}
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

func (c *ClientConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxRead.Done():
			c.ctxRead, c.cancelRead = context.WithCancel(context.Background())
		default:
		}
		// reset the deadline timer
		if c.readDeadline != nil {
			c.readDeadline.Stop()
		}
		c.readDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxRead.Done():
			default:
				c.cancelRead()
			}
		})
	} else {
		select {
		case <-c.ctxRead.Done():
		default:
			c.cancelRead()
		}
	}
	return nil
}

func (c *ClientConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if now := time.Now(); t.After(now) {
		// refresh the deadline if the deadline has been exceeded
		select {
		case <-c.ctxWrite.Done():
			c.ctxWrite, c.cancelWrite = context.WithCancel(context.Background())
		default:
		}
		if c.writeDeadline != nil {
			c.writeDeadline.Stop()
		}
		c.writeDeadline = time.AfterFunc(t.Sub(now), func() {
			c.deadlineMu.Lock()
			defer c.deadlineMu.Unlock()
			select {
			case <-c.ctxWrite.Done():
			default:
				c.cancelWrite()
			}
		})
	} else {
		select {
		case <-c.ctxWrite.Done():
		default:
			c.cancelWrite()
		}
	}
	return nil
}

func (c *ClientConn) LocalAddr() net.Addr {
	return nil
}

func (c *ClientConn) RemoteAddr() net.Addr {
	return nil
}

type Dialer struct {
	protocol.StatelessDialer
	ServiceName   string
	ServerName    string
	Address       string
	AllowInsecure bool

	initOnce  sync.Once
	lifecycle *netproxy.SingleSession[*grpc.ClientConn]
}

var _ netproxy.StatefulDialer = (*Dialer)(nil)

func (d *Dialer) session() *netproxy.SingleSession[*grpc.ClientConn] {
	d.initOnce.Do(func() {
		d.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*grpc.ClientConn]{
			Establish:   d.establish,
			IsConnected: func(cc *grpc.ClientConn) bool { return cc.GetState() == connectivity.Ready },
			Recover:     d.recover,
			Observe:     d.observe,
			Close:       (*grpc.ClientConn).Close,
		})
	})
	return d.lifecycle
}

func (d *Dialer) Snapshot() netproxy.StateEvent {
	return d.session().Snapshot()
}

func (d *Dialer) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return d.session().WatchState(ctx)
}

func (d *Dialer) dialOptions() ([]grpc.DialOption, error) {
	roots, err := cert.GetSystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system certificate pool: %w", err)
	}
	return []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName:         d.ServerName,
			RootCAs:            roots,
			InsecureSkipVerify: d.AllowInsecure,
		})),
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return d.ParentDialer.DialContext(ctx, "tcp", address)
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithBlock(),
	}, nil
}

func (d *Dialer) Connect(ctx context.Context) error {
	return d.session().Connect(ctx)
}

func (d *Dialer) establish(ctx context.Context) (*grpc.ClientConn, error) {
	if d.Address == "" {
		return nil, fmt.Errorf("grpc proxy address is empty")
	}
	options, err := d.dialOptions()
	if err != nil {
		return nil, err
	}
	return grpc.DialContext(ctx, d.Address, options...)
}

func (d *Dialer) recover(ctx context.Context, cc *grpc.ClientConn) (bool, error) {
	cc.Connect()
	for {
		state := cc.GetState()
		switch state {
		case connectivity.Ready:
			return false, nil
		case connectivity.Shutdown:
			return true, nil
		}
		if !cc.WaitForStateChange(ctx, state) {
			return false, ctx.Err()
		}
	}
}

func (d *Dialer) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*grpc.ClientConn]) {
	cc := handle.Resource()
	for {
		state := cc.GetState()
		var current bool
		switch state {
		case connectivity.Ready:
			current = handle.Transition(netproxy.SessionConnected, nil)
		case connectivity.Idle, connectivity.Connecting:
			current = handle.Transition(netproxy.SessionConnecting, nil)
		case connectivity.TransientFailure:
			current = handle.Transition(netproxy.SessionDisconnected, fmt.Errorf("grpc transport entered transient failure"))
		case connectivity.Shutdown:
			current = handle.Transition(netproxy.SessionDisconnected, net.ErrClosed)
		}
		if !current {
			return
		}
		if state == connectivity.Shutdown || !cc.WaitForStateChange(ctx, state) {
			return
		}
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	switch network {
	case "tcp":
		cc, err := d.session().Current()
		if err != nil {
			return nil, err
		}
		client := proto.NewGunServiceClient(cc)

		clientX := client.(proto.GunServiceClientX)
		serviceName := d.ServiceName
		if serviceName == "" {
			serviceName = "GunService"
		}
		// ctx is the lifetime of the tun
		ctxStream, streamCloser := context.WithCancel(context.Background())
		tun, err := common.Invoke(ctx, func() (proto.GunService_TunClient, error) {
			return clientX.TunCustomName(ctxStream, serviceName)
		}, streamCloser)
		if err != nil {
			return nil, err
		}
		return NewClientConn(tun, streamCloser), nil
	case "udp":
		return nil, fmt.Errorf("%w: grpc+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (d *Dialer) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: grpc+udp", netproxy.UnsupportedTunnelTypeError)
}

func (d *Dialer) Close() error {
	return d.session().Close()
}
