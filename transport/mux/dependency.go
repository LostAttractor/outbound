package mux

import "github.com/daeuniverse/outbound/netproxy"

func (c *Conn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
