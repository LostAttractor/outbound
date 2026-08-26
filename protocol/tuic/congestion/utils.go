package congestion

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/bbr"
	"github.com/daeuniverse/outbound/protocol/tuic/congestion/brutal"
	"github.com/daeuniverse/quic-go"
)

func UseBBR(conn *quic.Conn) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		bbr.GetInitialPacketSize(conn.RemoteAddr()),
	))
}

func UseBrutal(conn *quic.Conn, tx uint64) {
	conn.SetCongestionControl(brutal.NewBrutalSender(tx))
}
