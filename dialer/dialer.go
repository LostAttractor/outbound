package dialer

import (
	"fmt"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

var (
	UnexpectedFieldErr  = fmt.Errorf("unexpected field")
	InvalidParameterErr = fmt.Errorf("invalid parameters")
)

type ExtraOption struct {
	AllowInsecure       bool
	TlsImplementation   string
	TlsFragment         bool
	TlsFragmentLength   string
	TlsFragmentInterval string
	UtlsImitate         string
	BandwidthMaxTx      string
	BandwidthMaxRx      string
	UDPHopInterval      time.Duration
}

type Property struct {
	Name     string
	Address  string
	Protocol string
	Link     string
}

type Dialer interface {
	Dialer(option *ExtraOption, parentDialer netproxy.Dialer) (netproxy.Dialer, error)
}

// BuildRuntime adds one builder layer while preserving the parent's Session
// and owned resources. On success, the returned Runtime owns parent.
func BuildRuntime(builder Dialer, option *ExtraOption, parent *netproxy.Runtime) (*netproxy.Runtime, error) {
	d, err := builder.Dialer(option, parent.Dialer)
	if err != nil {
		return nil, err
	}
	return netproxy.ComposeRuntime(d, parent), nil
}
