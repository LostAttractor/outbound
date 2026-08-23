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
}

// SingleSessionHandle is the identity of one installed resource. A stale
// handle can no longer publish state or disconnect a replacement resource.
type SingleSessionHandle[T any] struct {
	owner    *SingleSession[T]
	resource T
	cancel   context.CancelFunc
}

func (h *SingleSessionHandle[T]) Resource() T { return h.resource }

func (h *SingleSessionHandle[T]) Transition(state SessionState, cause error) bool {
	if h == nil || state > SessionConnected {
		return false
	}
	s := h.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.current != h {
		return false
	}
	s.state.Transition(state, cause)
	return true
}

// Disconnect invalidates and closes this handle's resource. It returns false
// when the handle is stale or the lifecycle is already closed.
func (h *SingleSessionHandle[T]) Disconnect(cause error) bool {
	if h == nil {
		return false
	}
	s := h.owner
	s.mu.RLock()
	stale := s.ctx.Err() != nil || s.current != h
	s.mu.RUnlock()
	if stale {
		return false
	}
	select {
	case s.operation <- struct{}{}:
		defer func() { <-s.operation }()
	case <-s.ctx.Done():
		return false
	}
	s.mu.Lock()
	if s.ctx.Err() != nil || s.current != h {
		s.mu.Unlock()
		return false
	}
	resource := s.detachLocked()
	s.state.Transition(SessionDisconnected, cause)
	s.mu.Unlock()
	s.recordCloseError(s.closeHandle(resource))
	return true
}

type SingleSessionConfig[T any] struct {
	Establish func(context.Context) (T, error)
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
	return &SingleSession[T]{
		config:    config,
		operation: make(chan struct{}, 1),
		state:     NewStateBroadcaster(SessionDisconnected),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (s *SingleSession[T]) Snapshot() StateEvent { return s.state.Snapshot() }

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
	if connected {
		if err := connectCtx.Err(); err != nil {
			s.mu.Unlock()
			return err
		}
		s.state.Transition(SessionConnected, nil)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if current != nil && s.config.Recover != nil {
		return s.recoverCurrent(connectCtx, current)
	}

	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return net.ErrClosed
	}
	current = s.detachLocked()
	s.state.Transition(SessionConnecting, nil)
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
	s.state.Transition(SessionConnecting, nil)
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
			s.state.Transition(SessionDisconnected, operationErr)
			s.mu.Unlock()
			return operationErr
		}
		snapshot := s.state.Snapshot()
		connected := err == nil
		if s.config.IsConnected != nil {
			connected = s.config.IsConnected(current.resource)
		}
		if connected {
			s.state.Transition(SessionConnected, nil)
			s.mu.Unlock()
			return nil
		}
		if err == nil {
			err = snapshot.Cause
			if err == nil {
				err = ErrNotConnected
			}
		}
		s.state.Transition(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}

	resource := s.detachLocked()
	if operationErr != nil {
		s.state.Transition(SessionDisconnected, operationErr)
	} else if err != nil {
		s.state.Transition(SessionDisconnected, err)
	} else {
		s.state.Transition(SessionConnecting, nil)
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
	resource, err := s.config.Establish(ctx)
	s.mu.Lock()
	if err != nil {
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			return net.ErrClosed
		}
		if operationErr := ctx.Err(); operationErr != nil {
			s.state.Transition(SessionDisconnected, operationErr)
			s.mu.Unlock()
			return operationErr
		}
		s.state.Transition(SessionDisconnected, err)
		s.mu.Unlock()
		return err
	}
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return net.ErrClosed
	}
	if operationErr := ctx.Err(); operationErr != nil {
		s.state.Transition(SessionDisconnected, operationErr)
		s.mu.Unlock()
		s.recordCloseError(s.closeResource(resource))
		return operationErr
	}
	handle := &SingleSessionHandle[T]{owner: s, resource: resource}
	s.current = handle
	s.state.Transition(SessionConnected, nil)
	if s.config.Observe == nil {
		s.mu.Unlock()
		return nil
	}
	observerCtx, observerCancel := context.WithCancel(context.Background())
	handle.cancel = observerCancel
	s.observers.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.observers.Done()
		s.config.Observe(observerCtx, handle)
	}()
	return nil
}

func (s *SingleSession[T]) Current() (T, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ctx.Err() != nil {
		var zero T
		return zero, net.ErrClosed
	}
	if s.current == nil || s.state.Snapshot().State != SessionConnected {
		var zero T
		return zero, ErrNotConnected
	}
	return s.current.resource, nil
}

func (s *SingleSession[T]) detachLocked() *SingleSessionHandle[T] {
	current := s.current
	s.current = nil
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
		s.state.Transition(SessionClosed, nil)
		s.mu.Unlock()

		s.operation <- struct{}{}
		<-s.operation
		s.observers.Wait()
		s.recordCloseError(s.closeHandle(current))
	})
	return s.cleanupErr
}
