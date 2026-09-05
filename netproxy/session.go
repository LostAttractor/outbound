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
	// PublisherID identifies a logical event source, including channels whose
	// physical transport identity cannot be observed. It is not a ResourceRef.
	PublisherID      uint64
	Seq              uint64
	State            SessionState
	Cause            error
	Resource         ResourceRef
	ReadinessVersion uint64
	EpisodeID        uint64
	Accepting        bool
	UsableCapacity   int
	RecoveryExecutor RecoveryExecutor
	RecoveryRequired bool
	RecoveryPhase    string
	BlockedBy        string
	Layer            FailureLayer
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
	return newStateBroadcaster(StateEvent{State: initial, Accepting: initial == SessionConnected, UsableCapacity: boolCapacity(initial == SessionConnected)})
}

func newStateBroadcaster(initial StateEvent) *StateBroadcaster {
	if initial.PublisherID == 0 {
		initial.PublisherID = NewResourceRef().OwnerID
	}
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

func boolCapacity(accepting bool) int {
	if accepting {
		return 1
	}
	return 0
}

func (b *StateBroadcaster) publishLocked(state SessionState, cause error) bool {
	event := b.current
	event.State, event.Cause = state, cause
	event.Accepting = state == SessionConnected
	event.UsableCapacity = boolCapacity(event.Accepting)
	return b.publishEventWithReadinessLocked(event, true)
}

// Publish commits owner facts. Seq is the diagnostic revision; readiness only
// changes when usable dependencies change, never for a retry countdown alone.
// Resource owners supply EpisodeID; the broadcaster does not infer accidents.
func (b *StateBroadcaster) Publish(event StateEvent) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current.State == SessionClosed {
		return false
	}
	return b.publishEventWithReadinessLocked(event, true)
}
func (b *StateBroadcaster) publishEventWithReadinessLocked(event StateEvent, resourceAffectsReadiness bool) bool {
	previous := b.current
	if event.PublisherID == 0 {
		event.PublisherID = previous.PublisherID
	}
	event.Seq = previous.Seq + 1
	requestedReadiness := event.ReadinessVersion
	event.ReadinessVersion = previous.ReadinessVersion
	if previous.State != event.State || previous.Accepting != event.Accepting ||
		resourceAffectsReadiness && previous.Resource != event.Resource && (previous.Accepting || event.Accepting) {
		event.ReadinessVersion++
	}
	if requestedReadiness > event.ReadinessVersion {
		event.ReadinessVersion = requestedReadiness
	}
	b.current = event
	for watcher := range b.watchers {
		watcher.enqueue(event)
		if event.State == SessionClosed {
			watcher.finish(false)
		}
	}
	if event.State == SessionClosed {
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
	aggregate := StateEvent{State: SessionConnected, Accepting: true, UsableCapacity: 1, RecoveryExecutor: RecoveryDaemon, RecoveryPhase: "ready"}
	if len(s.states) == 0 {
		return aggregate
	}
	// Diagnostic attribution and chain readiness are separate. Prefer the first
	// unready dependency, otherwise retain the first useful pool diagnostic;
	// when healthy the outermost session is the user-facing resource.
	selected := len(s.states) - 1
	selectedFailure := false
	capacity := s.states[0].UsableCapacity
	executor := RecoveryLibraryManaged
	required := false
	state := SessionConnected
	accepting := true
	for i, child := range s.states {
		required = required || child.RecoveryRequired
		gate := child.State == SessionConnected && child.Accepting
		if child.RecoveryExecutor != RecoveryLibraryManaged {
			executor = RecoveryDaemon
		}
		if child.State == SessionClosed {
			selected = i
			state = SessionClosed
			accepting = false
			selectedFailure = true
			break
		}
		if !gate {
			accepting = false
			if child.State == SessionDisconnected || !child.Accepting && child.State == SessionConnected {
				if state != SessionDisconnected {
					selected = i
					selectedFailure = true
				}
				state = SessionDisconnected
			} else if state == SessionConnected {
				selected = i
				selectedFailure = true
				state = SessionConnecting
			}
		} else {
			capacity = min(capacity, child.UsableCapacity)
			if child.Cause != nil && !selectedFailure {
				selected = i
				selectedFailure = true
			}
		}
	}
	aggregate = s.states[selected]
	aggregate.State, aggregate.Accepting, aggregate.RecoveryExecutor = state, accepting, executor
	if !accepting {
		capacity = 0

	}
	// Capacity is the minimum currently usable shared-resource count along the
	// chain; it is not a promise about protocol stream limits.
	aggregate.UsableCapacity = capacity
	aggregate.RecoveryRequired = required
	return aggregate
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
	readinessChanged := s.states[index].ReadinessVersion != event.ReadinessVersion
	s.states[index] = event
	aggregate := s.aggregateLocked()
	current := s.state.Snapshot()
	aggregate.ReadinessVersion = current.ReadinessVersion
	if readinessChanged {
		aggregate.ReadinessVersion++
	}
	if aggregate.State != current.State || aggregate.Cause != current.Cause || aggregate.Accepting != current.Accepting || aggregate.ReadinessVersion != current.ReadinessVersion || aggregate.RecoveryExecutor != current.RecoveryExecutor || aggregate.RecoveryPhase != current.RecoveryPhase || aggregate.BlockedBy != current.BlockedBy || aggregate.UsableCapacity != current.UsableCapacity || aggregate.Resource != current.Resource || aggregate.EpisodeID != current.EpisodeID || aggregate.Layer != current.Layer || aggregate.RecoveryRequired != current.RecoveryRequired || aggregate.PublisherID != current.PublisherID {
		s.state.mu.Lock()
		if s.state.current.State != SessionClosed {
			s.state.publishEventWithReadinessLocked(aggregate, false)
		}
		s.state.mu.Unlock()
	}
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
	for i, child := range s.children {
		event := child.Snapshot()
		if !s.update(i, event) {
			return net.ErrClosed
		}
		if event.State != SessionConnected || !event.Accepting {
			return ErrDependencyInvalid
		}
	}
	return nil
}

func (s *SessionGroup) Snapshot() StateEvent {
	for i, child := range s.children {
		s.update(i, child.Snapshot())
	}
	return s.state.Snapshot()
}

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
	if event.State != SessionConnected || !event.Accepting {
		return ErrNotConnected
	}
	return nil
}
