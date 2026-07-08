package zeroconf

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// TestRecv4DoesNotBusySpinOnDeadSocket verifies the recvErrBackoff fix.
//
// When the underlying socket is in a persistent error state but Shutdown() was
// never called (s.shouldShutdown still open) — exactly what an OS-level socket
// teardown produces on iOS during a network transition (ENOTCONN) — recv4 used
// to loop on ReadFrom errors with no backoff, busy-spinning at ~1.6M syscalls/s
// and pegging a core. With the backoff it must throttle to a handful of
// iterations, not a spin.
func TestRecv4DoesNotBusySpinOnDeadSocket(t *testing.T) {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	pc := ipv4.NewPacketConn(uc)

	s := &Server{shouldShutdown: make(chan struct{})}
	s.refCount.Add(1)

	recvStats.mu.Lock()
	base := recvStats.readErrs
	recvStats.mu.Unlock()

	// Simulate the OS tearing the socket down WITHOUT Server.Shutdown() being
	// called — so shouldShutdown stays open and the loop has no reason to exit.
	uc.Close()

	go s.recv4(pc)
	time.Sleep(200 * time.Millisecond)

	recvStats.mu.Lock()
	spun := recvStats.readErrs - base
	recvStats.mu.Unlock()

	// Stop the loop and let the goroutine drain (also exercises the shutdown case
	// inside the backoff select).
	close(s.shouldShutdown)
	s.refCount.Wait()

	t.Logf("recv4 error iterations in 200ms (backoff %s..%s): %d", recvErrBackoffMin, recvErrBackoffMax, spun)
	if spun == 0 {
		t.Fatalf("recv4 never attempted a read")
	}
	// A busy-spin would be tens/hundreds of thousands. With growing backoff
	// starting at 50ms, a 200ms window yields only a few iterations. Any small
	// bound proves the spin is gone; allow generous slack for scheduler jitter.
	if spun > 50 {
		t.Fatalf("recv4 is busy-spinning on the dead socket: %d iterations in 200ms (backoff not applied)", spun)
	}
}
