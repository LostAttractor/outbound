package smux

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/xtaci/smux"
)

type smuxSlot struct {
	lifecycle  *netproxy.SingleSession[*smuxResource]
	activated  bool
	connecting int
	pending    int
	state      netproxy.StateEvent
}

type smuxPool struct {
	slots []*smuxSlot
	state *netproxy.StateBroadcaster

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	cursor    int
	watchers  sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func newSmuxPool(owner *Smux, maxConnections int) *smuxPool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &smuxPool{
		state:  netproxy.NewStateBroadcaster(netproxy.SessionDisconnected),
		ctx:    ctx,
		cancel: cancel,
		slots:  make([]*smuxSlot, maxConnections),
	}
	for i := range p.slots {
		p.slots[i] = &smuxSlot{lifecycle: netproxy.NewSingleSession(netproxy.SingleSessionConfig[*smuxResource]{
			Establish:   owner.establish,
			IsConnected: smuxResourceConnected,
			Observe:     owner.observe,
			Close: func(resource *smuxResource) error {
				err := resource.session.Close()
				if errors.Is(err, io.ErrClosedPipe) {
					return nil
				}
				return err
			},
		})}
	}
	return p
}

func smuxResourceConnected(resource *smuxResource) bool {
	return !resource.monitor.broken.Load() && !resource.session.IsClosed()
}

func (p *smuxPool) Snapshot() netproxy.StateEvent { return p.state.Snapshot() }

func (p *smuxPool) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return p.state.WatchState(ctx)
}

func (p *smuxPool) activateLocked(slot *smuxSlot) {
	if slot.activated {
		return
	}
	slot.activated = true
	slot.state = slot.lifecycle.Snapshot()
	events := slot.lifecycle.WatchState(p.ctx)
	p.watchers.Add(1)
	go func() {
		defer p.watchers.Done()
		for event := range events {
			p.mu.Lock()
			if p.ctx.Err() != nil {
				p.mu.Unlock()
				return
			}
			if event.Seq > slot.state.Seq {
				slot.state = event
				p.publishStateLocked(event.Cause)
			}
			p.mu.Unlock()
		}
	}()
}

func (p *smuxPool) syncSlotStateLocked(slot *smuxSlot) {
	event := slot.lifecycle.Snapshot()
	if event.Seq > slot.state.Seq {
		slot.state = event
	}
}

func (p *smuxPool) syncStatesLocked() {
	for _, slot := range p.slots {
		if slot.activated {
			p.syncSlotStateLocked(slot)
		}
	}
}

func (p *smuxPool) publishStateLocked(cause error) {
	if p.ctx.Err() != nil {
		return
	}
	connecting := false
	for _, slot := range p.slots {
		if !slot.activated {
			continue
		}
		if _, connected := p.connectedResourceLocked(slot); connected {
			p.state.Transition(netproxy.SessionConnected, nil)
			return
		}
		if slot.connecting > 0 || slot.state.State == netproxy.SessionConnecting {
			connecting = true
		} else if cause == nil && slot.state.State == netproxy.SessionDisconnected {
			cause = slot.state.Cause
		}
	}
	if connecting {
		p.state.Transition(netproxy.SessionConnecting, nil)
		return
	}
	p.state.Transition(netproxy.SessionDisconnected, cause)
}

func (p *smuxPool) connectedResourceLocked(slot *smuxSlot) (*smuxResource, bool) {
	resource, err := slot.lifecycle.Current()
	if err != nil || !smuxResourceConnected(resource) {
		return nil, false
	}
	return resource, true
}

func (p *smuxPool) connectedSlotLocked() *smuxSlot {
	for _, slot := range p.slots {
		if slot.activated {
			if _, connected := p.connectedResourceLocked(slot); !connected {
				continue
			}
			return slot
		}
	}
	return nil
}

func (p *smuxPool) connectionSlotLocked() *smuxSlot {
	for _, slot := range p.slots {
		if slot.connecting > 0 {
			return slot
		}
	}
	for _, slot := range p.slots {
		if !slot.activated || slot.lifecycle.Snapshot().State == netproxy.SessionDisconnected {
			return slot
		}
	}
	return p.slots[0]
}

func (p *smuxPool) Connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return net.ErrClosed
	}
	if p.connectedSlotLocked() != nil {
		p.syncStatesLocked()
		p.publishStateLocked(nil)
		p.mu.Unlock()
		return nil
	}
	p.syncStatesLocked()
	p.publishStateLocked(nil)
	slot := p.connectionSlotLocked()
	p.activateLocked(slot)
	slot.connecting++
	p.publishStateLocked(nil)
	p.mu.Unlock()

	err := slot.lifecycle.Connect(ctx)
	p.mu.Lock()
	slot.connecting--
	p.syncSlotStateLocked(slot)
	closed := p.ctx.Err() != nil
	p.publishStateLocked(err)
	p.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	return err
}

func (p *smuxPool) reserve(ctx context.Context, excluded map[*smuxSlot]struct{}, allowExpand bool) (*smuxSlot, *smux.Session, error) {
	var connectionErr error
	for {
		p.mu.Lock()
		if p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, nil, net.ErrClosed
		}

		var (
			best           *smuxSlot
			bestSession    *smux.Session
			bestLoad       int
			waiting        *smuxSlot
			waitingLoad    int
			connectedCount int
		)
		start := p.cursor
		p.cursor = (p.cursor + 1) % len(p.slots)
		for offset := range len(p.slots) {
			slot := p.slots[(start+offset)%len(p.slots)]
			if !slot.activated {
				continue
			}
			resource, connected := p.connectedResourceLocked(slot)
			if !connected {
				if slot.connecting > 0 {
					if _, skip := excluded[slot]; !skip && (waiting == nil || slot.pending < waitingLoad) {
						waiting = slot
						waitingLoad = slot.pending
					}
				}
				continue
			}
			connectedCount++
			if _, skip := excluded[slot]; skip {
				continue
			}
			load := resource.session.NumStreams() + slot.pending
			if best == nil || load < bestLoad {
				best = slot
				bestSession = resource.session
				bestLoad = load
			}
		}

		var expansion *smuxSlot
		if allowExpand && ((best != nil && bestLoad > 0) || (best == nil && len(excluded) > 0)) {
			for offset := range len(p.slots) {
				slot := p.slots[(start+offset)%len(p.slots)]
				if _, skip := excluded[slot]; skip || slot.connecting > 0 {
					continue
				}
				if !slot.activated {
					expansion = slot
					break
				}
				if slot.lifecycle.Snapshot().State != netproxy.SessionConnecting {
					if _, connected := p.connectedResourceLocked(slot); !connected {
						expansion = slot
						break
					}
				}
			}
		}

		if expansion != nil {
			failover := best == nil
			p.activateLocked(expansion)
			expansion.connecting++
			expansion.pending++
			p.syncStatesLocked()
			p.publishStateLocked(nil)
			p.mu.Unlock()

			err := expansion.lifecycle.Connect(ctx)
			p.mu.Lock()
			expansion.connecting--
			p.syncSlotStateLocked(expansion)
			closed := p.ctx.Err() != nil
			if err != nil || closed {
				expansion.pending--
			}
			p.publishStateLocked(err)
			if err == nil && !closed {
				resource, currentErr := expansion.lifecycle.Current()
				if currentErr == nil && smuxResourceConnected(resource) {
					p.mu.Unlock()
					return expansion, resource.session, nil
				}
				expansion.pending--
				p.mu.Unlock()
				if currentErr == nil {
					currentErr = netproxy.ErrNotConnected
				}
				err = currentErr
			} else {
				p.mu.Unlock()
			}
			if closed {
				return nil, nil, net.ErrClosed
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, ctxErr
			}
			connectionErr = errors.Join(connectionErr, err)
			if failover {
				excluded[expansion] = struct{}{}
			} else {
				allowExpand = false
			}
			continue
		}

		if waiting != nil && (best == nil || waitingLoad <= bestLoad) {
			failover := best == nil
			waiting.connecting++
			waiting.pending++
			p.mu.Unlock()
			err := waiting.lifecycle.Connect(ctx)
			p.mu.Lock()
			waiting.connecting--
			p.syncSlotStateLocked(waiting)
			closed := p.ctx.Err() != nil
			p.publishStateLocked(err)
			p.mu.Unlock()
			if closed {
				p.release(waiting)
				return nil, nil, net.ErrClosed
			}
			if err != nil {
				p.release(waiting)
				if ctxErr := ctx.Err(); ctxErr != nil {
					return nil, nil, ctxErr
				}
				connectionErr = errors.Join(connectionErr, err)
				if failover {
					excluded[waiting] = struct{}{}
				} else {
					allowExpand = false
				}
				continue
			}
			resource, err := waiting.lifecycle.Current()
			if err != nil || !smuxResourceConnected(resource) {
				p.release(waiting)
				if err == nil {
					err = netproxy.ErrNotConnected
				}
				connectionErr = errors.Join(connectionErr, err)
				if failover {
					excluded[waiting] = struct{}{}
				} else {
					allowExpand = false
				}
				continue
			}
			return waiting, resource.session, nil
		}

		if best != nil {
			best.pending++
			p.mu.Unlock()
			return best, bestSession, nil
		}
		p.mu.Unlock()

		if connectedCount > 0 || len(excluded) > 0 {
			return nil, nil, errors.Join(connectionErr, netproxy.ErrNotConnected)
		}
		if err := p.Connect(ctx); err != nil {
			return nil, nil, err
		}
	}
}

func (p *smuxPool) release(slot *smuxSlot) {
	p.mu.Lock()
	if slot.pending > 0 {
		slot.pending--
	}
	p.mu.Unlock()
}

func (p *smuxPool) OpenStream(ctx context.Context) (*smux.Stream, error) {
	excluded := make(map[*smuxSlot]struct{}, len(p.slots))
	var openErr error
	for len(excluded) < len(p.slots) {
		slot, session, err := p.reserve(ctx, excluded, true)
		if err != nil {
			return nil, errors.Join(openErr, err)
		}
		stream, err := openStream(ctx, session, func() { p.release(slot) })
		if err == nil {
			return stream, nil
		}
		openErr = errors.Join(openErr, err)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		_ = session.Close()
		excluded[slot] = struct{}{}
	}
	return nil, openErr
}

func (p *smuxPool) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.cancel()
		p.state.Transition(netproxy.SessionClosed, nil)
		p.mu.Unlock()
		for i := len(p.slots) - 1; i >= 0; i-- {
			p.closeErr = errors.Join(p.closeErr, p.slots[i].lifecycle.Close())
		}
		p.watchers.Wait()
	})
	return p.closeErr
}
