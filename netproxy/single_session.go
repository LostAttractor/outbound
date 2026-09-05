package netproxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

// SingleSession owns one shared transport resource. Callbacks must honor
// cancellation and must not synchronously call Connect or Close. Observe may
// use its handle to publish transitions or disconnect its resource.
type SingleSession[T any] struct {
	config SingleSessionConfig[T]

	operation chan struct{}
	state     *StateBroadcaster
	ctx       context.Context
	cancel    context.CancelFunc

	mu         sync.RWMutex
	current    *SingleSessionHandle[T]
	observers  sync.WaitGroup
	cleanupErr error
	closeOnce  sync.Once
	ref        ResourceRef
	// A reconnect attempt may pass through Connecting with no cause before
	// reporting failure. Keep its accident open until the resource is ready.
	failureEpisode bool
}

// SingleSessionHandle is the identity of one installed resource. A stale
// handle can no longer publish state or disconnect a replacement resource.
type SingleSessionHandle[T any] struct {
	owner         *SingleSession[T]
	resource      T
	cancel        context.CancelFunc
	ref           ResourceRef
	lease         *Lease
	dependencies  []*Lease
	disconnecting bool
}

func (h *SingleSessionHandle[T]) Resource() T      { return h.resource }
func (h *SingleSessionHandle[T]) Ref() ResourceRef { return h.ref }
func (h *SingleSessionHandle[T]) Lease() *Lease {
	h.owner.mu.RLock()
	defer h.owner.mu.RUnlock()
	return h.lease
}
func (h *SingleSessionHandle[T]) NewStreamLease() *Lease { return h.Lease().NewStream() }

func (h *SingleSessionHandle[T]) Transition(state SessionState, cause error) bool {
	if h == nil || state > SessionConnected {
		return false
	}
	s := h.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.current != h || h.disconnecting {
		return false
	}
	if state != SessionConnected {
		h.lease.Invalidate(cause)
	}
	if state == SessionConnected && !h.lease.Valid() {
		for _, parent := range h.dependencies {
			if !parent.Valid() {
				return false
			}
		}
		h.lease = NewLease(h.ref, h.dependencies...)
	}
	s.transitionLocked(state, cause)
	return true
}

// Disconnect invalidates and closes this handle's resource. It returns false
// when the handle is stale or the lifecycle is already closed.
func (h *SingleSessionHandle[T]) Disconnect(cause error) bool {
	if !h.markDisconnected(cause, false) {
		return false
	}
	h.cleanupDisconnected()
	return true
}

// Invalidate synchronously revokes allocation and publishes the root cause,
// then schedules blocking cleanup. Use this in data-plane Read/Write paths.
func (h *SingleSessionHandle[T]) Invalidate(cause error) bool {
	if !h.markDisconnected(cause, true) {
		return false
	}
	go func() { defer h.owner.observers.Done(); h.cleanupDisconnected() }()
	return true
}
func (h *SingleSessionHandle[T]) markDisconnected(cause error, worker bool) bool {
	if h == nil {
		return false
	}
	s := h.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.current != h || h.disconnecting {
		return false
	}
	h.disconnecting = true
	h.lease.Invalidate(cause)
	s.transitionLocked(SessionDisconnected, cause)
	s.phaseLocked("cleanup", "")
	if worker {
		s.observers.Add(1)
	}
	return true
}
func (h *SingleSessionHandle[T]) cleanupDisconnected() {
	s := h.owner
	select {
	case s.operation <- struct{}{}:
		defer func() { <-s.operation }()
	case <-s.ctx.Done():
		return
	}
	s.mu.Lock()
	if s.ctx.Err() != nil || s.current != h {
		s.mu.Unlock()
		return
	}
	resource := s.detachLocked()
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(resource))
	s.mu.Lock()
	if s.ctx.Err() == nil && s.current == nil {
		s.phaseLocked("queued", "")
	}
	s.mu.Unlock()
}

type SingleSessionConfig[T any] struct {
	Layer            FailureLayer
	RecoveryExecutor RecoveryExecutor
	// LogicalChannel reports no physical resource identity: library-owned
	// transports may be replaced without an observable one-to-one channel mapping.
	LogicalChannel bool
	Establish      func(context.Context) (T, error)
	// IsConnected optionally verifies a retained resource before Connect's
	// connected fast path. It must not block or call lifecycle methods.
	IsConnected func(T) bool
	// Recover optionally reconnects a retained but disconnected resource and
	// requires IsConnected to verify the result.
	// Returning replace asks SingleSession to close it and establish a new one.
	// Otherwise the resource is retained, including when an error is returned.
	Recover func(context.Context, T) (replace bool, err error)
	Observe func(context.Context, *SingleSessionHandle[T])
	Close   func(T) error
}

func NewSingleSession[T any](config SingleSessionConfig[T]) *SingleSession[T] {
	if config.Recover != nil && config.IsConnected == nil {
		panic("SingleSession Recover requires IsConnected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &SingleSession[T]{
		ref:       NewResourceRef(),
		config:    config,
		operation: make(chan struct{}, 1),
		state:     NewStateBroadcaster(SessionDisconnected),
		ctx:       ctx,
		cancel:    cancel,
	}
	s.ref.Generation = 0
	if config.RecoveryExecutor == "" {
		s.config.RecoveryExecutor = RecoveryDaemon
	}
	initial := s.state.current
	initial.Layer, initial.RecoveryExecutor = s.config.Layer, s.config.RecoveryExecutor
	s.state.current = initial
	return s
}

func (s *SingleSession[T]) transitionLocked(state SessionState, cause error) {
	event := s.state.Snapshot()
	ref := s.ref
	if s.config.LogicalChannel {
		ref = ResourceRef{}
	}
	accepting := state == SessionConnected
	newFailure := cause != nil && !accepting && state != SessionClosed && !s.failureEpisode
	if event.State == state && event.Resource == ref && event.Accepting == accepting && !newFailure {
		return
	}
	if newFailure {
		event.EpisodeID++
		s.failureEpisode = true
	} else if accepting && cause == nil {
		s.failureEpisode = false
	}
	event.State, event.Cause, event.Resource = state, cause, ref
	event.BlockedBy = ""
	switch state {
	case SessionConnected:
		event.RecoveryPhase = "ready"
	case SessionConnecting:
		event.RecoveryPhase = "connecting"
	case SessionClosed:
		event.RecoveryPhase = "stopped"
	case SessionDisconnected:
		event.RecoveryPhase = "queued"
		if s.config.RecoveryExecutor == RecoveryLibraryManaged {
			event.RecoveryPhase = "connecting"
		}
	}
	event.Accepting, event.UsableCapacity = accepting, boolCapacity(accepting)
	event.Layer, event.RecoveryExecutor = s.config.Layer, s.config.RecoveryExecutor
	s.state.Publish(event)
}
func (s *SingleSession[T]) phaseLocked(phase, blockedBy string) {
	event := s.state.Snapshot()
	if event.RecoveryPhase == phase && event.BlockedBy == blockedBy {
		return
	}
	event.RecoveryPhase, event.BlockedBy = phase, blockedBy
	s.state.Publish(event)
}
func (s *SingleSession[T]) Snapshot() StateEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil && !s.current.lease.Valid() && s.state.Snapshot().State == SessionConnected {
		fact := ClassifyFailure(s.current.lease.Cause())
		fact.Resource, fact.Scope = s.current.Ref(), ScopeSharedResource
		if fact.Layer == LayerUnknown || fact.Layer == "" {
			fact.Layer = s.config.Layer
		}
		s.transitionLocked(SessionDisconnected, WrapFailure(s.current.lease.Cause(), fact))
		s.phaseLocked("cleanup", "")
	}
	return s.state.Snapshot()
}

func (s *SingleSession[T]) WatchState(ctx context.Context) <-chan StateEvent {
	return s.state.WatchState(ctx)
}

func (s *SingleSession[T]) Connect(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.operation <- struct{}{}:
		defer func() { <-s.operation }()
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	connectCtx, cancel := NewDialTimeoutContextFrom(ctx)
	defer cancel()
	stopClose := context.AfterFunc(s.ctx, cancel)
	defer stopClose()
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	current := s.current
	connected := current != nil && s.state.Snapshot().State == SessionConnected
	if current != nil && s.config.IsConnected != nil {
		connected = s.config.IsConnected(current.resource)
	}
	if current != nil && !current.lease.Valid() {
		connected = false
	}
	if connected {
		if err := connectCtx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		s.transitionLocked(SessionConnected, nil)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if current != nil && !current.disconnecting && s.config.Recover != nil {
		return s.recoverCurrent(connectCtx, current)
	}

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	current = s.detachLocked()
	s.transitionLocked(SessionConnecting, nil)
	if current != nil {
		s.phaseLocked("cleanup", "")
	}
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(current))
	return s.establishAndInstall(connectCtx)
}

func (s *SingleSession[T]) recoverCurrent(ctx context.Context, current *SingleSessionHandle[T]) error {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.transitionLocked(SessionConnecting, nil)
	s.mu.Unlock()
	replace, err := s.config.Recover(ctx, current.resource)
	operationErr := ctx.Err()

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if !replace {
		if operationErr != nil {
			s.transitionLocked(SessionDisconnected, operationErr)
			s.mu.Unlock()
			return operationErr
		}
		snapshot := s.state.Snapshot()
		connected := err == nil
		if s.config.IsConnected != nil {
			connected = s.config.IsConnected(current.resource)
		}
		if connected {
			for _, parent := range current.dependencies {
				if !parent.Valid() {
					s.transitionLocked(SessionDisconnected, ErrDependencyInvalid)
					s.mu.Unlock()
					return ErrDependencyInvalid
				}
			}
			if !current.lease.Valid() {
				current.lease = NewLease(current.ref, current.dependencies...)
			}
			s.transitionLocked(SessionConnected, nil)
			s.mu.Unlock()
			return nil
		}
		if err == nil {
			err = snapshot.Cause
			if err == nil {
				err = ErrNotConnected
			}
		}
		s.transitionLocked(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}

	resource := s.detachLocked()
	if operationErr != nil {
		s.transitionLocked(SessionDisconnected, operationErr)
	} else if err != nil {
		s.transitionLocked(SessionDisconnected, err)
	} else {
		s.transitionLocked(SessionConnecting, nil)
	}
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(resource))
	if operationErr != nil {
		return operationErr
	}
	if err != nil {
		return err
	}
	return s.establishAndInstall(ctx)
}

func (s *SingleSession[T]) establishAndInstall(ctx context.Context) error {
	s.mu.Lock()
	s.phaseLocked("connecting", "")
	s.mu.Unlock()
	establishCtx, dependencies := collectDependencies(ctx)
	resource, err := s.config.Establish(establishCtx)
	s.mu.Lock()
	if err != nil {
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return net.ErrClosed
		}
		if operationErr := ctx.Err(); operationErr != nil {
			s.transitionLocked(SessionDisconnected, operationErr)
			s.mu.Unlock()
			return operationErr
		}
		s.transitionLocked(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return net.ErrClosed
	}
	if operationErr := ctx.Err(); operationErr != nil {
		s.transitionLocked(SessionDisconnected, operationErr)
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return operationErr
	}
	parents := dependencies.snapshot()
	for _, parent := range parents {
		if !parent.Valid() {
			cause := WrapFailure(ErrDependencyInvalid, Failure{Scope: ScopeSharedResource, Layer: s.config.Layer, Phase: OpHandshake})
			s.transitionLocked(SessionDisconnected, cause)
			s.mu.Unlock()
			s.recordCloseError(s.closeResource(resource))
			return cause
		}
	}
	s.ref.Generation++
	ref := s.ref
	if s.config.LogicalChannel {
		ref = ResourceRef{}
	}
	observerCtx, observerCancel := context.WithCancel(context.Background())
	handle := &SingleSessionHandle[T]{owner: s, resource: resource, ref: ref, lease: NewLease(ref, parents...), dependencies: parents, cancel: observerCancel}
	if !handle.lease.Valid() {
		observerCancel()
		s.transitionLocked(SessionDisconnected, ErrDependencyInvalid)
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return ErrDependencyInvalid
	}
	s.current = handle
	s.transitionLocked(SessionConnected, nil)
	if s.config.Observe != nil {
		s.observers.Add(1)
		go func() { defer s.observers.Done(); s.config.Observe(observerCtx, handle) }()
	}
	for _, parent := range parents {
		s.observers.Add(1)
		go func(parent *Lease) {
			defer s.observers.Done()
			select {
			case <-observerCtx.Done():
				return
			case <-parent.Done():
			}
			fact := ClassifyFailure(parent.Cause())
			fact.Resource, fact.Scope = handle.Ref(), ScopeSharedResource
			if fact.Layer == LayerUnknown || fact.Layer == "" {
				fact.Layer = s.config.Layer
			}
			handle.Disconnect(WrapFailure(parent.Cause(), fact))
		}(parent)
	}
	s.mu.Unlock()
	return nil
}

func (s *SingleSession[T]) CurrentHandle() (*SingleSessionHandle[T], error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if s.current == nil || !s.current.lease.Valid() || s.state.Snapshot().State != SessionConnected {
		return nil, ErrNotConnected
	}
	if s.config.IsConnected != nil && !s.config.IsConnected(s.current.resource) {
		return nil, ErrNotConnected
	}
	return s.current, nil
}
func (s *SingleSession[T]) Current() (T, error) {
	handle, err := s.CurrentHandle()
	if err != nil {
		var zero T
		return zero, err
	}
	return handle.resource, nil
}

func (s *SingleSession[T]) detachLocked() *SingleSessionHandle[T] {
	current := s.current
	s.current = nil
	if current != nil {
		current.lease.Invalidate(WrapFailure(net.ErrClosed, Failure{Resource: current.Ref(), Origin: OriginLocalCleanup, Scope: ScopeSharedResource, Layer: s.config.Layer}))
	}
	if current != nil && current.cancel != nil {
		current.cancel()
	}
	return current
}

func (s *SingleSession[T]) closeHandle(handle *SingleSessionHandle[T]) error {
	if handle == nil {
		return nil
	}
	return s.closeResource(handle.resource)
}

func (s *SingleSession[T]) closeResource(resource T) error {
	if s.config.Close == nil {
		return nil
	}
	return s.config.Close(resource)
}

func (s *SingleSession[T]) recordCloseError(err error) {
	s.cleanupErr = errors.Join(s.cleanupErr, err)
}

func (s *SingleSession[T]) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.cancel()
		current := s.detachLocked()
		s.transitionLocked(SessionClosed, nil)
		s.mu.Unlock()

		s.operation <- struct{}{}
		<-s.operation
		s.observers.Wait()
		s.recordCloseError(s.closeHandle(current))
	})
	return s.cleanupErr
}
