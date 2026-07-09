package zeroconf

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
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

func TestRecvLoopSurvivesTransientReadErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion("_test._tcp.local.", dns.TypePTR)
	packet, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	readFrom := func(b []byte) (int, net.Addr, error) {
		calls++
		switch {
		case calls <= 2:
			return 0, nil, fmt.Errorf("transient read error %d", calls)
		case calls == 3:
			return copy(b, packet), nil, nil
		default:
			<-ctx.Done()
			return 0, nil, net.ErrClosed
		}
	}

	msgCh := make(chan *dns.Msg, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		recvLoop(ctx, readFrom, msgCh)
	}()

	select {
	case <-msgCh:
		// the loop survived the transient errors and delivered the packet
	case <-time.After(2 * time.Second):
		t.Fatal("no message received after transient read errors; recv loop died")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recv loop did not stop on context cancellation")
	}
}

func TestRecvLoopStopsOnClosedConn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	readFrom := func(b []byte) (int, net.Addr, error) {
		return 0, nil, fmt.Errorf("read udp4: %w", net.ErrClosed)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		recvLoop(ctx, readFrom, make(chan *dns.Msg, 1))
	}()

	select {
	case <-done:
		// a closed connection is terminal: no retries, no goroutine leak
	case <-time.After(time.Second):
		t.Fatal("recv loop kept running on a closed connection")
	}
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
