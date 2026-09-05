package trojan

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/transport/tls"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/transport/grpc"
	"github.com/daeuniverse/outbound/transport/httpupgrade"
	"github.com/daeuniverse/outbound/transport/ws"
)

func init() {
	dialer.FromLinkRegister("trojan", NewTrojan)
	dialer.FromLinkRegister("trojan-go", NewTrojan)
}

type Trojan struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Password      string `json:"password"`
	Sni           string `json:"sni"`
	Type          string `json:"type"`
	Encryption    string `json:"encryption"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	ServiceName   string `json:"serviceName"`
	AllowInsecure bool   `json:"allowInsecure"`
	Protocol      string `json:"protocol"`
}

func NewTrojan(link string) (dialer.Builder, *dialer.Property, error) {
	s, err := ParseTrojanURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func (s *Trojan) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (layer netproxy.Layer, err error) {
	layer.Data = upstream
	proxyAddress := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	defer func() {
		if err != nil {
			err = errors.Join(err, layer.Close())
			layer = netproxy.Layer{}
		}
	}()

	var encryption []string
	if s.Encryption != "" && s.Encryption != "none" {
		encryption = strings.SplitN(s.Encryption, ";", 3)
		if len(encryption) != 3 || encryption[0] != "ss" || encryption[1] == "" {
			err = fmt.Errorf("invalid Trojan encryption: expected ss;method;password")
			return
		}
	}

	if s.Type != "grpc" { // grpc contains tls
		tlsConfig := tls.TLSConfig{
			Host:          proxyAddress,
			Sni:           s.Sni,
			AllowInsecure: s.AllowInsecure,
		}
		if err = layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return
		}
	}
	switch s.Type {
	case "ws":
		host := s.Host
		if host == "" {
			host = s.Server
		}
		wsConfig := &ws.WsConfig{
			Scheme:   "ws",
			Host:     proxyAddress,
			Path:     s.Path,
			Hostname: host,
		}
		if err = layer.AppendResult(wsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return
		}
	case "grpc":
		transport := &grpc.Dialer{
			ParentDialer: layer.Data,
			ServiceName:  s.ServiceName,
			Address:      proxyAddress,
			TLSConfig:    &cryptotls.Config{ServerName: s.Sni, InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure},
		}
		layer.Data = transport
		layer.Sessions = append(layer.Sessions, transport)
		layer.Resources = append(layer.Resources, transport)
	case "httpupgrade":
		u := url.URL{
			Scheme: "http",
			Host:   proxyAddress,
			RawQuery: url.Values{
				"host": []string{s.Host},
				"path": []string{s.Path},
			}.Encode(),
		}

		layer.Data, err = httpupgrade.NewDialer(u.String(), layer.Data)
		if err != nil {
			return
		}
	}
	if encryption != nil {
		var encrypted netproxy.Dialer
		encrypted, err = shadowsocks.NewDialer(layer.Data, protocol.Header{
			ProxyAddress: proxyAddress,
			Cipher:       encryption[1],
			Password:     encryption[2],
		})
		if err != nil {
			return
		}
		layer.Data = shadowsocksTransport{encrypted.(*shadowsocks.Dialer)}
	}
	err = layer.AppendResult(protocol.Build("trojanc", layer.Data, protocol.Header{
		ProxyAddress: proxyAddress,
		Password:     s.Password,
	}))
	return
}

// Trojan owns the destination header; this layer only encrypts its TCP carrier.
type shadowsocksTransport struct{ *shadowsocks.Dialer }

func (d shadowsocksTransport) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: Trojan Shadowsocks transport: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
	return d.DialTCPTransport(ctx)
}
func (shadowsocksTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: Trojan Shadowsocks transport requires TCP", netproxy.UnsupportedTunnelTypeError)
}

func ParseTrojanURL(u string) (data *Trojan, err error) {
	//trojan://password@server:port#escape(remarks)
	t, err := url.Parse(u)
	if err != nil {
		err = fmt.Errorf("invalid trojan format")
		return
	}
	allowInsecure, _ := strconv.ParseBool(t.Query().Get("allowInsecure"))
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allow_insecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("allowinsecure"))
	}
	if !allowInsecure {
		allowInsecure, _ = strconv.ParseBool(t.Query().Get("skipVerify"))
	}
	sni := t.Query().Get("peer")
	if sni == "" {
		sni = t.Query().Get("sni")
	}
	if sni == "" {
		sni = t.Hostname()
	}
	port, err := strconv.Atoi(t.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	data = &Trojan{
		Name:          t.Fragment,
		Server:        t.Hostname(),
		Port:          port,
		Password:      t.User.Username(),
		Sni:           sni,
		AllowInsecure: allowInsecure,
		Protocol:      "trojan",
	}
	if t.Query().Get("type") != "" {
		t.Scheme = "trojan-go"
	}
	if t.Scheme == "trojan-go" {
		data.Protocol = "trojan-go"
		data.Encryption = t.Query().Get("encryption")
		data.Host = t.Query().Get("host")
		data.Path = t.Query().Get("path")
		data.Type = t.Query().Get("type")
		data.ServiceName = t.Query().Get("serviceName")
		if data.Type == "grpc" && data.ServiceName == "" {
			data.ServiceName = data.Path
		}
	}
	return data, nil
}

func (t *Trojan) ExportToURL() string {
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.User(t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)

	if t.Protocol == "trojan-go" {
		u.Scheme = "trojan-go"
		common.SetValue(&q, "host", t.Host)
		common.SetValue(&q, "encryption", t.Encryption)
		common.SetValue(&q, "type", t.Type)
		common.SetValue(&q, "path", t.Path)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
