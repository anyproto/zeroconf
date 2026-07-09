package zeroconf

import (
	"context"
	"net"
	"testing"
	"time"
)

// An interface that exists on no system: joining its multicast group fails, so
// newClient errors out before the mainloop (the usual channel closer) starts.
var unjoinableIfaces = []net.Interface{{Index: 0xFFFF, Name: "nonexistent0", Flags: net.FlagUp | net.FlagMulticast}}

func requireClosed(t *testing.T, entries <-chan *ServiceEntry) {
	t.Helper()
	select {
	case _, ok := <-entries:
		if ok {
			t.Fatal("expected entries channel to be closed, got an entry")
		}
	case <-time.After(time.Second):
		t.Fatal("entries channel not closed after an error return")
	}
}

func TestBrowseClosesEntriesOnClientError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	entries := make(chan *ServiceEntry)
	err := Browse(ctx, mdnsService, mdnsDomain, entries, SelectIfaces(unjoinableIfaces))
	if err == nil {
		t.Fatal("expected Browse to fail with unjoinable interfaces")
	}
	requireClosed(t, entries)
}

func TestLookupClosesEntriesOnClientError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	entries := make(chan *ServiceEntry)
	err := Lookup(ctx, mdnsName, mdnsService, mdnsDomain, entries, SelectIfaces(unjoinableIfaces))
	if err == nil {
		t.Fatal("expected Lookup to fail with unjoinable interfaces")
	}
	requireClosed(t, entries)
}
