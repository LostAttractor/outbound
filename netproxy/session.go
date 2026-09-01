package netproxy

import (
	"context"
	"errors"
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

// SessionGroup combines session control and state without owning the sessions.
// Runtime stops the group before closing the separately tracked resources.
type SessionGroup struct {
	children []Session
	state    *StateBroadcaster
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	states   []StateEvent
	stopOnce sync.Once
}

func NewSessionGroup(children ...Session) *SessionGroup {
	ctx, cancel := context.WithCancel(context.Background())
	s := &SessionGroup{
		children: children,
		ctx:      ctx,
		cancel:   cancel,
		states:   make([]StateEvent, len(children)),
	}
	for i, child := range children {
		s.states[i] = child.Snapshot()
	}
	s.state = newStateBroadcaster(s.aggregateLocked())
	for i, child := range children {
		s.wg.Add(1)
		go s.watch(i, child)
	}
	return s
}

func (s *SessionGroup) aggregateLocked() StateEvent {
	state := SessionConnected
	var cause error
	for _, child := range s.states {
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

func (s *SessionGroup) watch(index int, child Session) {
	defer s.wg.Done()
	for event := range child.WatchState(s.ctx) {
		if !s.update(index, event) {
			return
		}
	}
}

func (s *SessionGroup) update(index int, event StateEvent) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	if event.Seq <= s.states[index].Seq {
		return true
	}
	s.states[index] = event
	aggregate := s.aggregateLocked()
	s.state.update(aggregate.State, aggregate.Cause)
	return true
}

func (s *SessionGroup) Connect(ctx context.Context) error {
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	for i, child := range s.children {
		err := child.Connect(ctx)
		if !s.update(i, child.Snapshot()) {
			return net.ErrClosed
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SessionGroup) Snapshot() StateEvent { return s.state.Snapshot() }

func (s *SessionGroup) WatchState(ctx context.Context) <-chan StateEvent {
	return s.state.WatchState(ctx)
}

// Stop stops aggregation without closing the child sessions.
func (s *SessionGroup) Stop() {
	s.stopOnce.Do(func() {
		s.cancel()
		s.state.Transition(SessionClosed, nil)
		s.wg.Wait()
	})
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
