package proto

import (
	"bytes"

	"github.com/daeuniverse/outbound/transport/shadowsocksr/internal/crypto"
)

var constructors = map[string]func() IProtocol{
	"origin":           NewOrigin,
	"auth_aes128_md5":  NewAuthAES128MD5,
	"auth_aes128_sha1": NewAuthAES128SHA1,
	"auth_chain_a":     NewAuthChainA,
	"auth_chain_b":     NewAuthChainB,
	"auth_sha1_v4":     NewAuthSHA1v4,
}

type hmacMethod func(key []byte, data []byte) []byte
type hashDigestMethod func(data []byte) []byte
type rndMethod func(dataLength int, random *crypto.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int
type pktRndMethod func(random *crypto.Shift128plusContext, lastHash []byte) int

type IProtocol interface {
	InitWithServerInfo(s *ServerInfo)
	Encode(data []byte, dst *bytes.Buffer) error
	Decode(data []byte, dst *bytes.Buffer) (int, error)
	EncodePkt(buf *bytes.Buffer) error
	DecodePkt(data []byte) ([]byte, error)
	GetOverhead() int
}

type AuthData struct {
	clientID     []byte
	connectionID uint32
}

func NewProtocol(name string) IProtocol {
	if create := constructors[name]; create != nil {
		return create()
	}
	return nil
}

type ServerInfo struct {
	Param string

	TcpMss   int
	IV       []byte
	Key      []byte
	AddrLen  int
	Overhead int
}
