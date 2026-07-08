package zeroconf

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ---- #p2p mDNS receive hot-path instrumentation ----
//
// recv4/recv6 are the CPU hot path on mobile: every mDNS packet on the LAN
// (most of it unrelated Bonjour / AirPlay / printer / IoT traffic) is received
// and parsed here. Logging every packet would flood the device log AND add so
// much CPU that it would distort the very thing we are measuring, so instead we
// accumulate counters and flush one summary line per window.
//
// This whole file is throwaway debug instrumentation; delete it (and its call
// sites in recv4/recv6/parsePacket) to remove.

const recvStatsWindow = 5 * time.Second

var recvStats recvStatsAgg

type recvStatsAgg struct {
	mu          sync.Mutex
	windowStart time.Time
	packets     int64             // successfully received datagrams
	bytes       int64             // total bytes received
	queries     int64             // inbound questions (msg.Response == false)
	responses   int64             // inbound answers   (msg.Response == true)
	forUs       int64             // packets referencing our service (_anytype._tcp)
	unpackErr   int64             // datagrams that failed to parse as DNS
	readErrs    int64             // ReadFrom errors (busy-spin detector)
	lastErr     string            // most recent ReadFrom error string
	bySource    map[[4]byte]int64 // per source-IP packet count (no per-packet alloc)
}

// initLocked lazily starts the first window. Caller must hold the lock.
func (a *recvStatsAgg) initLocked(now time.Time) {
	if a.bySource == nil {
		a.bySource = make(map[[4]byte]int64)
		a.windowStart = now
	}
}

// recvStatRaw records one received datagram. Called from recv4/recv6 right after
// ReadFrom, before parsing, so malformed packets are counted too.
func recvStatRaw(from net.Addr, n int) {
	now := time.Now()
	recvStats.mu.Lock()
	recvStats.initLocked(now)
	recvStats.packets++
	recvStats.bytes += int64(n)
	if udp, ok := from.(*net.UDPAddr); ok {
		if ip4 := udp.IP.To4(); ip4 != nil {
			var key [4]byte
			copy(key[:], ip4)
			recvStats.bySource[key]++
		}
	}
	if now.Sub(recvStats.windowStart) >= recvStatsWindow {
		recvStats.flushLocked(now)
	}
	recvStats.mu.Unlock()
}

// recvStatErr records a ReadFrom error. Critically, this ALSO drives the window
// flush: during a busy-spin every read errors, so recvStatRaw is never called
// and the summary would otherwise never print. A pure error window shows up as
// "0 pkts ... readErrs=<huge>/s lastErr='...use of closed network connection'".
func recvStatErr(err error) {
	now := time.Now()
	recvStats.mu.Lock()
	recvStats.initLocked(now)
	recvStats.readErrs++
	if err != nil {
		recvStats.lastErr = err.Error()
	}
	if now.Sub(recvStats.windowStart) >= recvStatsWindow {
		recvStats.flushLocked(now)
	}
	recvStats.mu.Unlock()
}

// recvStatClassify records the parsed shape of a datagram. Called from
// parsePacket after a successful Unpack.
func recvStatClassify(isResponse, forUs bool) {
	recvStats.mu.Lock()
	if isResponse {
		recvStats.responses++
	} else {
		recvStats.queries++
	}
	if forUs {
		recvStats.forUs++
	}
	recvStats.mu.Unlock()
}

// recvStatUnpackErr records a datagram that failed to parse as a DNS message.
func recvStatUnpackErr() {
	recvStats.mu.Lock()
	recvStats.unpackErr++
	recvStats.mu.Unlock()
}

func (a *recvStatsAgg) flushLocked(now time.Time) {
	elapsed := now.Sub(a.windowStart).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	type talker struct {
		ip  [4]byte
		cnt int64
	}
	talkers := make([]talker, 0, len(a.bySource))
	for ip, c := range a.bySource {
		talkers = append(talkers, talker{ip, c})
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i].cnt > talkers[j].cnt })
	top := ""
	for i := 0; i < len(talkers) && i < 5; i++ {
		t := talkers[i]
		top += fmt.Sprintf(" %d.%d.%d.%d=%d", t.ip[0], t.ip[1], t.ip[2], t.ip[3], t.cnt)
	}

	errInfo := ""
	if a.readErrs > 0 {
		errInfo = fmt.Sprintf(" readErrs=%d (%.0f/s) lastErr=%q", a.readErrs, float64(a.readErrs)/elapsed, a.lastErr)
	}
	tracef("#p2p recv-stats %.1fs: %d pkts (%.0f/s, %.1f KB/s) sources=%d queries=%d responses=%d forUs=%d unpackErr=%d%s top:%s\n",
		elapsed, a.packets, float64(a.packets)/elapsed, float64(a.bytes)/1024/elapsed,
		len(a.bySource), a.queries, a.responses, a.forUs, a.unpackErr, errInfo, top)

	a.windowStart = now
	a.packets = 0
	a.bytes = 0
	a.queries = 0
	a.responses = 0
	a.forUs = 0
	a.unpackErr = 0
	a.readErrs = 0
	a.lastErr = ""
	a.bySource = make(map[[4]byte]int64)
}

// packetForUs reports whether a parsed message references our own service, so we
// can see how much of the inbound flood is relevant vs. unrelated LAN noise.
func (s *Server) packetForUs(msg *dns.Msg) bool {
	if s.service == nil || s.service.Service == "" {
		return false
	}
	name := s.service.Service // e.g. "_anytype._tcp"
	for i := range msg.Question {
		if containsFold(msg.Question[i].Name, name) {
			return true
		}
	}
	for _, rr := range msg.Answer {
		if containsFold(rr.Header().Name, name) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return len(needle) == 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if lowerASCII(haystack[i+j]) != lowerASCII(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}
