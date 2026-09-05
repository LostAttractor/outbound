package tuic

import (
	"context"
	"errors"
	"testing"

	"github.com/daeuniverse/outbound/protocol/tuic/common"
)

func TestClientRingCloseStopsAndClosesClients(t *testing.T) {
	client := new(clientImpl)
	ring := newClientRing(func(func(int64)) *clientImpl { return client }, 0)
	ring.current = ring._insertAfterCurrent(&clientRingNode{cli: client, capability: -1})

	if err := ring.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.closed || ring.current != nil || ring.ring.Len() != 0 {
		t.Fatalf("closed ring retained state: clientClosed=%v current=%v len=%d", client.closed, ring.current, ring.ring.Len())
	}
	if err := ring.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// A late cleanup callback may still hold the allocation mutex.
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if _, err := ring.DialContext(context.Background(), nil); !errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("DialContextWithDialer after Close returned %v", err)
	}
}
