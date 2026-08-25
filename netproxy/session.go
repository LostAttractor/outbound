package netproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

var ErrNotConnected = errors.New("dialer session is not connected")

type SessionState uint8

const (
	SessionDisconnected SessionState = iota
	SessionConnecting
	SessionConnected
	SessionClosed
)

func (s SessionState) String() string {
	switch s {
	case SessionDisconnected:
		return "disconnected"
	case SessionConnecting:
		return "connecting"
	case SessionConnected:
		return "connected"
	case SessionClosed:
		return "closed"
	default:
		return "invalid"
	}
}

type StateEvent struct {
	Seq   uint64
	State SessionState
	Cause error
}

// Session is the lifecycle of a dialer-level shared connection. WatchState's
// first event is an atomic snapshot; subsequent events contain every state
// transition while the subscription remains active.
type Session interface {
	Connect(context.Context) error
	Snapshot() StateEvent
	WatchState(context.Context) <-chan StateEvent
}

// SessionOwner combines shared-connection control with resource ownership.
// Runtime exposes only Session and remains the sole public close boundary.
type SessionOwner interface {
	Session
	io.Closer
}

type StatefulDialer interface {
	Dialer
	SessionOwner
}

type stateWatcher struct {
	mu        sync.Mutex
	cond      *sync.Cond
	queue     []StateEvent
	accepting bool
	out       chan StateEvent
}

func newStateWatcher(initial StateEvent) *stateWatcher {
	w := &stateWatcher{
		queue:     []StateEvent{initial},
		accepting: true,
		out:       make(chan StateEvent),
	}
	w.cond = sync.NewCond(&w.mu)
	return w
}

func (w *stateWatcher) enqueue(event StateEvent) {
	w.mu.Lock()
	if w.accepting {
		w.queue = append(w.queue, event)
		w.cond.Signal()
	}
	w.mu.Unlock()
}

func (w *stateWatcher) finish(drop bool) {
	w.mu.Lock()
	if drop {
		w.queue = nil
	}
	w.accepting = false
	w.cond.Broadcast()
	w.mu.Unlock()
}

// StateBroadcaster implements the event side of Session. Protocols own the
// actual connection state and call Transition at its linearization point.
type StateBroadcaster struct {
	mu       sync.Mutex
	current  StateEvent
	watchers map[*stateWatcher]struct{}
}

func NewStateBroadcaster(initial SessionState) *StateBroadcaster {
	return newStateBroadcaster(StateEvent{State: initial})
}

func newStateBroadcaster(initial StateEvent) *StateBroadcaster {
	return &StateBroadcaster{
		current:  initial,
		watchers: make(map[*stateWatcher]struct{}),
	}
}

func (b *StateBroadcaster) Snapshot() StateEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

func (b *StateBroadcaster) WatchState(ctx context.Context) <-chan StateEvent {
	b.mu.Lock()
	w := newStateWatcher(b.current)
	closed := b.current.State == SessionClosed
	if !closed {
		b.watchers[w] = struct{}{}
	}
	b.mu.Unlock()

	if closed {
		w.finish(false)
	}
	go func() {
		stop := context.AfterFunc(ctx, func() { w.finish(true) })
		defer stop()
		defer close(w.out)
		defer func() {
			b.mu.Lock()
			delete(b.watchers, w)
			b.mu.Unlock()
		}()
		for {
			w.mu.Lock()
			for len(w.queue) == 0 && w.accepting {
				w.cond.Wait()
			}
			if len(w.queue) == 0 {
				w.mu.Unlock()
				return
			}
			event := w.queue[0]
			w.queue[0] = StateEvent{}
			w.queue = w.queue[1:]
			w.mu.Unlock()
			select {
			case w.out <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return w.out
}

// Transition publishes one event for an actual state transition. Closed is
// terminal. Protocols use a separate resource identity to reject stale events.
func (b *StateBroadcaster) Transition(state SessionState, cause error) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.State == SessionClosed || b.current.State == state {
		return false
	}
	return b.publishLocked(state, cause)
}

func (b *StateBroadcaster) update(state SessionState, cause error) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.State == SessionClosed || b.current.State == state && b.current.Cause == nil && cause == nil {
		return false
	}
	return b.publishLocked(state, cause)
}

func (b *StateBroadcaster) publishLocked(state SessionState, cause error) bool {
	b.current = StateEvent{Seq: b.current.Seq + 1, State: state, Cause: cause}
	event := b.current
	for watcher := range b.watchers {
		watcher.enqueue(event)
		if state == SessionClosed {
			watcher.finish(false)
		}
	}
	if state == SessionClosed {
		clear(b.watchers)
	}
	return true
}

type sessionDialer struct {
	Dialer
	SessionOwner
}

type closerGroup struct {
	closers []io.Closer
	once    sync.Once
	err     error
}

func (g *closerGroup) Close() error {
	g.once.Do(func() {
		for _, closer := range g.closers {
			g.err = errors.Join(g.err, closer.Close())
		}
	})
	return g.err
}

type managedSession struct {
	Session
	closer io.Closer
}

func (s *managedSession) Close() error { return s.closer.Close() }

type resourceDialer struct {
	Dialer
	io.Closer
}

// WithSession attaches a real session capability to a data-plane dialer.
func WithSession(dialer Dialer, session SessionOwner) StatefulDialer {
	return &sessionDialer{Dialer: dialer, SessionOwner: session}
}

// ComposeDialer preserves a parent's session and owned resources through a
// stateless wrapper. The returned dialer owns both inputs and closes them from
// the outside in.
func ComposeDialer(dialer, parent Dialer) Dialer {
	childSession, childStateful := dialer.(SessionOwner)
	parentSession, parentStateful := parent.(SessionOwner)

	var session SessionOwner
	switch {
	case childStateful && parentStateful:
		session = NewSessionGroup(parentSession, childSession)
	case childStateful:
		session = childSession
	case parentStateful:
		session = parentSession
	}

	closers := make([]io.Closer, 0, 3)
	if closer, ok := dialer.(io.Closer); ok && !childStateful {
		closers = append(closers, closer)
	}
	if session != nil {
		closers = append(closers, session)
	}
	if closer, ok := parent.(io.Closer); ok && !parentStateful {
		closers = append(closers, closer)
	}
	if len(closers) == 0 {
		return dialer
	}
	closer := &closerGroup{closers: closers}
	if session != nil {
		return WithSession(dialer, &managedSession{Session: session, closer: closer})
	}
	return &resourceDialer{Dialer: dialer, Closer: closer}
}

type SessionGroup struct {
	children  []SessionOwner
	state     *StateBroadcaster
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	states    []StateEvent
	closeOnce sync.Once
	closeErr  error
}

func NewSessionGroup(children ...SessionOwner) *SessionGroup {
	ctx, cancel := context.WithCancel(context.Background())
	g := &SessionGroup{
		children: children,
		ctx:      ctx,
		cancel:   cancel,
		states:   make([]StateEvent, len(children)),
	}
	for i, child := range children {
		g.states[i] = child.Snapshot()
	}
	g.state = newStateBroadcaster(g.aggregateLocked())
	for i, child := range children {
		g.wg.Add(1)
		go g.watch(i, child)
	}
	return g
}

func (g *SessionGroup) aggregateLocked() StateEvent {
	state := SessionConnected
	var cause error
	for _, child := range g.states {
		switch child.State {
		case SessionClosed:
			return StateEvent{State: SessionClosed, Cause: child.Cause}
		case SessionDisconnected:
			state = SessionDisconnected
			if cause == nil {
				cause = child.Cause
			}
		case SessionConnecting:
			if state == SessionConnected {
				state = SessionConnecting
				cause = child.Cause
			}
		}
	}
	return StateEvent{State: state, Cause: cause}
}

func (g *SessionGroup) watch(index int, child Session) {
	defer g.wg.Done()
	for event := range child.WatchState(g.ctx) {
		if !g.update(index, event) {
			return
		}
	}
}

func (g *SessionGroup) update(index int, event StateEvent) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx.Err() != nil {
		return false
	}
	if event.Seq <= g.states[index].Seq {
		return true
	}
	g.states[index] = event
	aggregate := g.aggregateLocked()
	g.state.update(aggregate.State, aggregate.Cause)
	return true
}

func (g *SessionGroup) Connect(ctx context.Context) error {
	if g.ctx.Err() != nil {
		return net.ErrClosed
	}
	for i, child := range g.children {
		err := child.Connect(ctx)
		if !g.update(i, child.Snapshot()) {
			return net.ErrClosed
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *SessionGroup) Snapshot() StateEvent { return g.state.Snapshot() }

func (g *SessionGroup) WatchState(ctx context.Context) <-chan StateEvent {
	return g.state.WatchState(ctx)
}

func (g *SessionGroup) Close() error {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.cancel()
		g.mu.Unlock()
		g.state.Transition(SessionClosed, nil)
		g.wg.Wait()
		for i := len(g.children) - 1; i >= 0; i-- {
			g.closeErr = errors.Join(g.closeErr, g.children[i].Close())
		}
	})
	return g.closeErr
}

// RequireConnected returns the current connected state without probing the
// network. It is intended for stateful DialContext and ListenPacket methods.
func RequireConnected(session Session) error {
	event := session.Snapshot()
	if event.State == SessionClosed {
		return net.ErrClosed
	}
	if event.State != SessionConnected {
		return ErrNotConnected
	}
	return nil
}
