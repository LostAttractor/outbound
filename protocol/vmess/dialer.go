package vmess

import (
	"context"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/google/uuid"
)

func init() {
	protocol.RegisterLayer("vmess", NewDialerFactory(protocol.ProtocolVMessTCP))
	protocol.RegisterLayer("vmess+tls+grpc", NewDialerFactory(protocol.ProtocolVMessTlsGrpc))
}

type Dialer struct {
	protocol          protocol.Protocol
	proxyAddress      string
	proxySNI          string
	grpcServiceName   string
	nextDialer        netproxy.Dialer
	metadata          protocol.Metadata
	key               []byte
	featurePacketAddr bool
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (*Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	cipher, _ := ParseCipherFromSecurity(Cipher(header.Cipher).ToSecurity())
	metadata.Cipher = string(cipher)

	// UUID mapping
	if l := len([]byte(header.Password)); l < 32 || l > 36 {
		header.Password = common.StringToUUID5(header.Password)
	}

	id, err := uuid.Parse(header.Password)
	if err != nil {
		return nil, err
	}
	//log.Trace("vmess.NewDialer: metadata: %v, password: %v", metadata, password)
	return &Dialer{
		proxyAddress:      header.ProxyAddress,
		proxySNI:          header.SNI,
		grpcServiceName:   header.Feature1.(string),
		nextDialer:        nextDialer,
		metadata:          metadata,
		key:               NewID(id).CmdKey(),
		featurePacketAddr: header.Flags&protocol.Flags_VMess_UsePacketAddr > 0,
	}, nil
}

func NewDialerFactory(proto protocol.Protocol) protocol.LayerCreator {
	return func(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Layer, error) {
		d, err := NewDialer(nextDialer, header)
		if err != nil {
			return netproxy.Layer{}, err
		}
		d.protocol = proto
		if proto == protocol.ProtocolVMessTlsGrpc {
			transport := &grpc.Dialer{
				StatelessDialer: protocol.StatelessDialer{ParentDialer: nextDialer},
				ServiceName:     d.grpcServiceName,
				ServerName:      d.proxySNI,
				Address:         d.proxyAddress,
			}
			d.nextDialer = transport
			return netproxy.Layer{
				Data:      d,
				Sessions:  []netproxy.Session{transport},
				Resources: []io.Closer{transport},
			}, nil
		}
		return netproxy.Layer{Data: d}, nil
	}
}

func (d *Dialer) DialTcp(ctx context.Context, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *Dialer) DialUdp(ctx context.Context, addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.Cipher = d.metadata.Cipher
		mdata.IsClient = d.metadata.IsClient
		if d.featurePacketAddr && magicNetwork.Network == "udp" {
			mdata.Hostname = SeqPacketMagicAddress
			mdata.Type = protocol.MetadataTypeDomain
		}

		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
		}.Encode()
		conn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
		if err != nil {
			return nil, err
		}

		return NewConn(conn, Metadata{
			Metadata: mdata,
			Network:  magicNetwork.Network,
		}, addr, d.key)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}
