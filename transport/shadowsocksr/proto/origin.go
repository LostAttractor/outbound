package proto

import (
	"bytes"
)

func init() {
	register("origin", NewOrigin)
}

type origin struct {
	ServerInfo
}

func NewOrigin() IProtocol {
	a := &origin{}
	return a
}

func (o *origin) InitWithServerInfo(s *ServerInfo) {
	o.ServerInfo = *s
}

func (o *origin) GetServerInfo() (s *ServerInfo) {
	return &o.ServerInfo
}

func (a *origin) EncodePkt(buf *bytes.Buffer) (err error) {
	return nil
}

func (a *origin) DecodePkt(in []byte) (out []byte, err error) {
	return in, nil
}

func (o *origin) Encode(data []byte, dst *bytes.Buffer) error {
	dst.Write(data)
	return nil
}

func (o *origin) Decode(data []byte, dst *bytes.Buffer) (int, error) {
	dst.Write(data)
	return len(data), nil
}

func (o *origin) GetOverhead() int {
	return 0
}
