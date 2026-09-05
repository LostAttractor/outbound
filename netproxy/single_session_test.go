package netproxy

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type singleSessionResource struct {
	closes atomic.Int32
}

func TestSingleSessionLifecycle(t *testing.T) {
	resource := new(singleSessionResource)
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	var session *SingleSession[*singleSessionResource]
	session = NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(context.Context) (*singleSessionResource, error) { return resource, nil },
		Observe: func(_ context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			if handle.Resource() == resource {
				observed <- handle
			}
		},
		Close: func(resource *singleSessionResource) error {
			resource.closes.Add(1)
			return nil
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current, err := session.Current(); err != nil || current != resource {
		t.Fatalf("Current() = %p, %v", current, err)
	}
	handle := <-observed
	if !handle.Disconnect(errors.New("lost")) {
		t.Fatal("current resource was treated as stale")
	}
	if state := session.Snapshot().State; state != SessionDisconnected {
		t.Fatalf("state = %s, want disconnected", state)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes = %d, want 1", got)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	if state := session.Snapshot().State; state != SessionClosed {
		t.Fatalf("state = %s, want closed", state)
	}
}

func TestSingleSessionCloseCancelsConnect(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(ctx context.Context) (*singleSessionResource, error) {
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return nil, ctx.Err()
		},
	})
	result := make(chan error, 1)
	go func() { result <- session.Connect(context.Background()) }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	<-canceled
	select {
	case <-closed:
		t.Fatal("Close returned before Connect released its resources")
	default:
	}
	close(release)
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Connect error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel Connect")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionCloseCleansLateResource(t *testing.T) {
	started := make(chan struct{})
	resource := new(singleSessionResource)
	cleanupErr := errors.New("late cleanup failed")
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(ctx context.Context) (*singleSessionResource, error) {
			close(started)
			<-ctx.Done()
			return resource, nil
		},
		Close: func(resource *singleSessionResource) error {
			resource.closes.Add(1)
			return cleanupErr
		},
	})
	connectResult := make(chan error, 1)
	go func() { connectResult <- session.Connect(context.Background()) }()
	<-started
	if err := session.Close(); !errors.Is(err, cleanupErr) {
		t.Fatalf("Close error = %v, want %v", err, cleanupErr)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("resource closes when Close returned = %d, want 1", got)
	}
	if err := <-connectResult; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Connect error = %v, want net.ErrClosed", err)
	}
}

func TestSingleSessionCallerCancellationRejectsLateResource(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	resource := new(singleSessionResource)
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(context.Context) (*singleSessionResource, error) {
			close(started)
			<-release
			return resource, nil
		},
		Close: func(resource *singleSessionResource) error {
			resource.closes.Add(1)
			return nil
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- session.Connect(ctx) }()
	<-started
	cancel()
	close(release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want context.Canceled", err)
	}
	if got := resource.closes.Load(); got != 1 {
		t.Fatalf("late resource closes = %d, want 1", got)
	}
	if state := session.Snapshot().State; state != SessionDisconnected {
		t.Fatalf("state = %s, want disconnected", state)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionConnectedFastPathRejectsCanceledCaller(t *testing.T) {
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(context.Context) (*singleSessionResource, error) {
			return new(singleSessionResource), nil
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := session.Connect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Connect error = %v, want context.Canceled", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionConnectedFastPathPublishesLiveState(t *testing.T) {
	resource := new(singleSessionResource)
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish:   func(context.Context) (*singleSessionResource, error) { return resource, nil },
		IsConnected: func(*singleSessionResource) bool { return true },
		Observe: func(ctx context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			observed <- handle
			<-ctx.Done()
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle := <-observed
	if !handle.Transition(SessionDisconnected, errors.New("stale observer state")) {
		t.Fatal("observer was treated as stale")
	}
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if current, err := session.Current(); err != nil || current != resource {
		t.Fatalf("Current() = %p, %v", current, err)
	}
	if state := session.Snapshot().State; state != SessionConnected {
		t.Fatalf("state = %s, want connected", state)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionRecoveryDoesNotOverwriteNewerState(t *testing.T) {
	resource := new(singleSessionResource)
	recoveryStarted := make(chan struct{})
	recoveryRelease := make(chan struct{})
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	newerErr := errors.New("newer observer state")
	var ready atomic.Bool
	ready.Store(true)
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish:   func(context.Context) (*singleSessionResource, error) { return resource, nil },
		IsConnected: func(*singleSessionResource) bool { return ready.Load() },
		Recover: func(context.Context, *singleSessionResource) (bool, error) {
			close(recoveryStarted)
			<-recoveryRelease
			return false, nil
		},
		Observe: func(ctx context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			observed <- handle
			<-ctx.Done()
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle := <-observed
	ready.Store(false)
	connectResult := make(chan error, 1)
	go func() { connectResult <- session.Connect(context.Background()) }()
	<-recoveryStarted
	if !handle.Transition(SessionDisconnected, newerErr) {
		t.Fatal("observer was treated as stale")
	}
	close(recoveryRelease)
	if err := <-connectResult; !errors.Is(err, newerErr) {
		t.Fatalf("Connect error = %v, want newer observer cause", err)
	}
	if snapshot := session.Snapshot(); snapshot.State != SessionDisconnected || !errors.Is(snapshot.Cause, newerErr) {
		t.Fatalf("snapshot = {%s %v}, want newer disconnected state", snapshot.State, snapshot.Cause)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionRecoveryUsesLiveStateAfterObserverChange(t *testing.T) {
	resource := new(singleSessionResource)
	recoveryStarted := make(chan struct{})
	recoveryRelease := make(chan struct{})
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	var ready atomic.Bool
	ready.Store(true)
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish:   func(context.Context) (*singleSessionResource, error) { return resource, nil },
		IsConnected: func(*singleSessionResource) bool { return ready.Load() },
		Recover: func(context.Context, *singleSessionResource) (bool, error) {
			close(recoveryStarted)
			<-recoveryRelease
			return false, nil
		},
		Observe: func(ctx context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			observed <- handle
			<-ctx.Done()
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle := <-observed
	ready.Store(false)
	connectResult := make(chan error, 1)
	go func() { connectResult <- session.Connect(context.Background()) }()
	<-recoveryStarted
	if !handle.Transition(SessionDisconnected, errors.New("transient")) {
		t.Fatal("observer was treated as stale")
	}
	ready.Store(true)
	close(recoveryRelease)
	if err := <-connectResult; err != nil {
		t.Fatalf("Connect rejected a recovered live resource: %v", err)
	}
	if state := session.Snapshot().State; state != SessionConnected {
		t.Fatalf("state = %s, want connected", state)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSingleSessionCloseWaitsForCleanupAndReportsError(t *testing.T) {
	resource := new(singleSessionResource)
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	cleanupStarted := make(chan struct{})
	cleanupRelease := make(chan struct{})
	cleanupErr := errors.New("cleanup failed")
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(context.Context) (*singleSessionResource, error) { return resource, nil },
		Observe: func(ctx context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			observed <- handle
			<-ctx.Done()
		},
		Close: func(*singleSessionResource) error {
			close(cleanupStarted)
			<-cleanupRelease
			return cleanupErr
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle := <-observed
	disconnected := make(chan bool, 1)
	go func() { disconnected <- handle.Disconnect(errors.New("lost")) }()
	<-cleanupStarted
	closed := make(chan error, 1)
	go func() { closed <- session.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned before cleanup completed")
	default:
	}
	close(cleanupRelease)
	if !<-disconnected {
		t.Fatal("Disconnect rejected the current resource")
	}
	if err := <-closed; !errors.Is(err, cleanupErr) {
		t.Fatalf("Close error = %v, want %v", err, cleanupErr)
	}
}

func TestSingleSessionRejectsTerminalObserverTransition(t *testing.T) {
	resource := new(singleSessionResource)
	observed := make(chan *SingleSessionHandle[*singleSessionResource], 1)
	session := NewSingleSession(SingleSessionConfig[*singleSessionResource]{
		Establish: func(context.Context) (*singleSessionResource, error) { return resource, nil },
		Observe: func(_ context.Context, handle *SingleSessionHandle[*singleSessionResource]) {
			observed <- handle
		},
	})
	if err := session.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	handle := <-observed
	if handle.Transition(SessionClosed, nil) {
		t.Fatal("observer published terminal state")
	}
	if !handle.Transition(SessionConnected, nil) {
		t.Fatal("duplicate current transition was treated as stale")
	}
	if state := session.Snapshot().State; state != SessionConnected {
		t.Fatalf("state = %s, want connected", state)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}
