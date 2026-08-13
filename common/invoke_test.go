package common

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInvokeReturnsResult(t *testing.T) {
	got, err := Invoke(context.Background(), func() (int, error) {
		return 42, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("result = %d, want 42", got)
	}
}

func TestInvokeCancellationDoesNotBlockWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	callback := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := Invoke(ctx, func() (int, error) {
			close(started)
			<-release
			return 42, nil
		}, func() { close(callback) })
		done <- err
	}()

	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	select {
	case <-callback:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback was not called")
	}

	close(release)
	// The buffered result channel lets the worker publish after Invoke returns.
	time.Sleep(10 * time.Millisecond)
}
