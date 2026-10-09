package zeroconf

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func stubInterfaceAddrs(t *testing.T, byIndex map[int][]string) {
	t.Helper()
	orig := interfaceAddrs
	t.Cleanup(func() { interfaceAddrs = orig })
	interfaceAddrs = func(ifIndex int) ([]net.Addr, error) {
		var res []net.Addr
		for _, cidr := range byIndex[ifIndex] {
			ip, n, err := net.ParseCIDR(cidr)
			if err != nil {
				t.Fatal(err)
			}
			n.IP = ip
			res = append(res, n)
		}
		return res, nil
	}
}

func addrsOf(rrs []dns.RR) (v4, v6 []string) {
	for _, rr := range rrs {
		switch r := rr.(type) {
		case *dns.A:
			v4 = append(v4, r.A.String())
		case *dns.AAAA:
			v6 = append(v6, r.AAAA.String())
		}
	}
	return
}

func TestAppendAddrsLinkLocal(t *testing.T) {
	const ifCable, ifWifi = 31, 4
	stubInterfaceAddrs(t, map[int][]string{
		ifCable: {"fe80::a886:c6ff:febd:f923/64", "fdf0::10/64"},
		ifWifi:  {"192.168.1.229/24", "fe80::1c57:dcff:fe84:9d64/64", "2a0d::10/64"},
	})
	s := &Server{
		service:         &ServiceEntry{HostName: "host.local.", AddrIPv4: []net.IP{net.ParseIP("192.168.1.229")}},
		linkLocalIfaces: map[int]struct{}{ifCable: {}},
	}

	for _, tc := range []struct {
		name    string
		ifIndex int
		wantV6  []string
	}{
		{"a listed interface adds only its own link-local", ifCable, []string{"fe80::a886:c6ff:febd:f923"}},
		{"an unlisted interface adds nothing", ifWifi, nil},
		{"no interface adds nothing", 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// when
			v4, v6 := addrsOf(s.appendAddrs(nil, 120, tc.ifIndex, false))

			// then
			if want := []string{"192.168.1.229"}; !reflect.DeepEqual(v4, want) {
				t.Errorf("A records = %v, want %v", v4, want)
			}
			if !reflect.DeepEqual(v6, tc.wantV6) {
				t.Errorf("AAAA records = %v, want %v", v6, tc.wantV6)
			}
		})
	}
}

func TestAppendAddrsLinkLocalWithoutFixedAddrs(t *testing.T) {
	// given: no fixed list, so appendAddrs falls back to the interface; a
	// listed interface must still announce its link-local only
	const ifCable = 31
	stubInterfaceAddrs(t, map[int][]string{
		ifCable: {"fe80::a886:c6ff:febd:f923/64", "fd12::1/64", "2001:db8::1/64"},
	})
	s := &Server{
		service:         &ServiceEntry{HostName: "host.local."},
		linkLocalIfaces: map[int]struct{}{ifCable: {}},
	}

	// when
	_, v6 := addrsOf(s.appendAddrs(nil, 120, ifCable, false))

	// then
	if want := []string{"fe80::a886:c6ff:febd:f923"}; !reflect.DeepEqual(v6, want) {
		t.Errorf("AAAA records = %v, want %v", v6, want)
	}
}

func TestAppendAddrsDoesNotWriteIntoTheServiceEntry(t *testing.T) {
	// given: a fixed IPv6 list with spare capacity
	const ifA, ifB = 31, 32
	stubInterfaceAddrs(t, map[int][]string{ifA: {"fe80::a/64"}, ifB: {"fe80::b/64"}})
	fixed := make([]net.IP, 1, 4)
	fixed[0] = net.ParseIP("fd00::1")
	s := &Server{
		service:         &ServiceEntry{HostName: "host.local.", AddrIPv6: fixed},
		linkLocalIfaces: map[int]struct{}{ifA: {}, ifB: {}},
	}

	// when
	_, onA := addrsOf(s.appendAddrs(nil, 120, ifA, false))
	_, onB := addrsOf(s.appendAddrs(nil, 120, ifB, false))

	// then
	if want := []string{"fd00::1", "fe80::a"}; !reflect.DeepEqual(onA, want) {
		t.Errorf("on A = %v, want %v", onA, want)
	}
	if want := []string{"fd00::1", "fe80::b"}; !reflect.DeepEqual(onB, want) {
		t.Errorf("on B = %v, want %v", onB, want)
	}
	if fixed[:2][1] != nil {
		t.Errorf("the service entry's backing array was written: %v", fixed[:2])
	}
}

func TestMainloopZonesLinkLocalByReceivingInterface(t *testing.T) {
	const ifCable = 31
	orig := interfaceZone
	t.Cleanup(func() { interfaceZone = orig })
	interfaceZone = func(ifIndex int) string {
		if ifIndex == ifCable {
			return "en16"
		}
		return strconv.Itoa(ifIndex)
	}

	answer := func() *dns.Msg {
		params := defaultParams("_anytype._tcp")
		instance := "peer1." + params.ServiceName()
		host := "iPhone.local."
		msg := new(dns.Msg)
		msg.Response = true
		msg.Answer = []dns.RR{
			&dns.PTR{Hdr: dns.RR_Header{Name: params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: instance},
		}
		msg.Extra = []dns.RR{
			&dns.SRV{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Port: 62654, Target: host},
			&dns.AAAA{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::a886:c6ff:febd:f9dc")},
			&dns.AAAA{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("2a0d::5")},
		}
		return msg
	}

	for _, tc := range []struct {
		name      string
		ifIndex   int
		wantZoned []netip.Addr
	}{
		{
			name:    "the receiving interface becomes the zone",
			ifIndex: ifCable,
			wantZoned: []netip.Addr{
				netip.MustParseAddr("fe80::a886:c6ff:febd:f9dc%en16"),
				netip.MustParseAddr("2a0d::5"),
			},
		},
		{
			name:      "an unknown receiving interface drops the link-local",
			ifIndex:   0,
			wantZoned: []netip.Addr{netip.MustParseAddr("2a0d::5")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// given
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			entries := make(chan *ServiceEntry, 1)
			params := defaultParams("_anytype._tcp")
			params.Entries = entries
			params.isBrowsing = true
			msgCh := make(chan receivedMsg, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				(&client{}).mainloop(ctx, params, msgCh)
			}()

			// when
			msgCh <- receivedMsg{msg: answer(), ifIndex: tc.ifIndex}

			// then
			select {
			case e := <-entries:
				if !reflect.DeepEqual(e.AddrIPv6Zoned, tc.wantZoned) {
					t.Errorf("AddrIPv6Zoned = %v, want %v", e.AddrIPv6Zoned, tc.wantZoned)
				}
				if len(e.AddrIPv6) != 2 {
					t.Errorf("AddrIPv6 = %v, want both addresses untouched", e.AddrIPv6)
				}
			case <-ctx.Done():
				t.Fatal("no entry delivered")
			}
			cancel()
			<-done
		})
	}
}

// mainloopFixture runs a browsing (or lookup) mainloop fed by hand.
type mainloopFixture struct {
	t        *testing.T
	ctx      context.Context
	cancel   context.CancelFunc
	params   *lookupParams
	entries  chan *ServiceEntry
	msgCh    chan receivedMsg
	done     chan struct{}
	instance string
	host     string
}

func newMainloopFixture(t *testing.T, cl *client, browsing bool, entriesBuf int) *mainloopFixture {
	t.Helper()
	orig := interfaceZone
	t.Cleanup(func() { interfaceZone = orig })
	interfaceZone = func(i int) string { return "if" + strconv.Itoa(i) }

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	params := defaultParams("_anytype._tcp")
	entries := make(chan *ServiceEntry, entriesBuf)
	params.Entries = entries
	params.isBrowsing = browsing
	if !browsing {
		params.stopProbing = make(chan struct{})
	}
	f := &mainloopFixture{
		t: t, ctx: ctx, cancel: cancel, params: params, entries: entries,
		msgCh: make(chan receivedMsg, 8), done: make(chan struct{}),
		instance: "peer1." + params.ServiceName(), host: "peer1.local.",
	}
	go func() {
		defer close(f.done)
		cl.mainloop(ctx, params, f.msgCh)
	}()
	// stop the loop before the zone stub is restored (cleanups run LIFO)
	t.Cleanup(func() {
		cancel()
		<-f.done
	})
	return f
}

// answer is a service answer with a service TTL and the given address
// records (TTL 120, as the server sends them).
func (f *mainloopFixture) answer(ttl uint32, addrs ...string) *dns.Msg {
	return f.answerTTL(ttl, 120, addrs...)
}

func (f *mainloopFixture) answerTTL(ttl, addrTTL uint32, addrs ...string) *dns.Msg {
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: f.params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: f.instance}}
	msg.Extra = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: f.instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}, Port: 4006, Target: f.host}}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip.To4() != nil {
			msg.Extra = append(msg.Extra, &dns.A{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: addrTTL}, A: ip})
		} else {
			msg.Extra = append(msg.Extra, &dns.AAAA{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: addrTTL}, AAAA: ip})
		}
	}
	return msg
}

func (f *mainloopFixture) send(msg *dns.Msg, ifIndex int) {
	f.msgCh <- receivedMsg{msg: msg, ifIndex: ifIndex}
}

func (f *mainloopFixture) next() *ServiceEntry {
	f.t.Helper()
	select {
	case e := <-f.entries:
		return e
	case <-f.ctx.Done():
		f.t.Fatal("no entry delivered")
		return nil
	}
}

func (f *mainloopFixture) none() {
	f.t.Helper()
	select {
	case e := <-f.entries:
		f.t.Errorf("unexpected delivery: %v %v", e.AddrIPv4, e.AddrIPv6Zoned)
	case <-time.After(100 * time.Millisecond):
	}
}

func addrStrings(e *ServiceEntry) []string {
	var res []string
	for _, ip := range e.AddrIPv4 {
		res = append(res, ip.String())
	}
	for _, a := range e.AddrIPv6Zoned {
		res = append(res, a.String())
	}
	return res
}

const ifWifi, ifCable = 4, 31

// flushed sets the cache-flush bit on the message's address records.
func flushed(msg *dns.Msg) *dns.Msg {
	for _, rr := range msg.Extra {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			rr.Header().Class |= qClassCacheFlush
		}
	}
	return msg
}

func cableClient() *client {
	return &client{ipv6Ifaces: map[int]struct{}{ifCable: {}}}
}

func TestMainloopMergesAnswersFromSelectedLinks(t *testing.T) {
	t.Run("a cable answer after a Wi-Fi answer delivers both", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)

		// when
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		first := f.next()
		first.AddrIPv4[0] = net.ParseIP("192.0.2.1") // the subscriber owns what it got
		f.send(f.answer(3600, "fe80::62"), ifCable)
		second := f.next()
		f.send(f.answer(3600, "fe80::62"), ifCable)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then
		if want := []string{"192.168.1.62", "fe80::62%if31"}; !reflect.DeepEqual(addrStrings(second), want) {
			t.Errorf("second delivery = %v, want %v", addrStrings(second), want)
		}
		f.none()
	})

	t.Run("an answer on one link does not renew another link's addresses", func(t *testing.T) {
		// given: Wi-Fi answered with a 1 s address TTL (service TTL 3600)
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answerTTL(3600, 1, "192.168.1.62"), ifWifi)
		f.next()
		time.Sleep(1100 * time.Millisecond)

		// when: the cable answers after the Wi-Fi address expired
		f.send(f.answer(3600, "fe80::62"), ifCable)

		// then
		if got, want := addrStrings(f.next()), []string{"fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a renewed link survives the cleanup of the delivery it came after", func(t *testing.T) {
		// given: both links, the cable renewed later with a long address TTL
		origCleanup := cleanupFreq
		cleanupFreq = 200 * time.Millisecond
		t.Cleanup(func() { cleanupFreq = origCleanup })
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answerTTL(1, 120, "192.168.1.62"), ifWifi)
		f.next()
		f.send(f.answerTTL(1, 120, "fe80::62"), ifCable)
		f.next()
		f.send(f.answerTTL(3600, 120, "fe80::62"), ifCable)
		time.Sleep(1500 * time.Millisecond) // past expiry plus a cleanup tick

		// when: Wi-Fi answers again after the deliveries expired
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then: redelivered (its delivery expired) with the cable still in
		if got, want := addrStrings(f.next()), []string{"192.168.1.62", "fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a partial answer never delivers an unresolved target", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answerTTL(3600, 1, "192.168.1.62"), ifWifi)
		f.next()
		f.send(f.answer(3600, "fe80::62"), ifCable)
		f.next()
		time.Sleep(1100 * time.Millisecond)

		// when: a PTR-only answer after the Wi-Fi address expired
		ptrOnly := f.answer(3600)
		ptrOnly.Extra = nil
		f.send(ptrOnly, ifWifi)

		// then: the known target is kept with the live cable address
		e := f.next()
		if e.Port != 4006 || e.HostName != f.host {
			t.Errorf("target = %s:%d, want %s:4006", e.HostName, e.Port, f.host)
		}
		if got, want := addrStrings(e), []string{"fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a goodbye on one link keeps the other link", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()
		f.send(f.answer(3600, "fe80::62"), ifCable)
		f.next()

		// when: the peer leaves Wi-Fi
		f.send(f.answerTTL(0, 0, "192.168.1.62"), ifWifi)

		// then
		if got, want := addrStrings(f.next()), []string{"fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a new port is delivered", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when
		moved := f.answer(3600, "192.168.1.62")
		moved.Extra[0].(*dns.SRV).Port = 4007
		f.send(moved, ifWifi)

		// then
		if e := f.next(); e.Port != 4007 {
			t.Errorf("port = %d, want 4007", e.Port)
		}
	})

	t.Run("a cache-flush answer retires the link's older addresses a second later", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "fe80::1"), ifCable)
		f.next()
		time.Sleep(1100 * time.Millisecond)

		// when
		f.send(flushed(f.answer(3600, "fe80::2")), ifCable)
		f.next() // fe80::2 added; fe80::1 still live for a second
		time.Sleep(1100 * time.Millisecond)
		f.send(flushed(f.answer(3600, "fe80::2")), ifCable)

		// then
		if got, want := addrStrings(f.next()), []string{"fe80::2%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a cache-flush set split over packets keeps every part", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when: one burst, two packets
		f.send(flushed(f.answer(3600, "fe80::62")), ifCable)
		f.next()
		f.send(flushed(f.answer(3600, "2001:db8::62")), ifCable)
		time.Sleep(1100 * time.Millisecond)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then: no delivery dropped the link-local address
		f.none()
	})

	t.Run("a cache-flush goodbye withdraws only its own address", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "fe80::62", "2001:db8::62"), ifCable)
		f.next()
		time.Sleep(1100 * time.Millisecond)

		// when
		f.send(flushed(f.answerTTL(3600, 0, "2001:db8::62")), ifCable)
		time.Sleep(1100 * time.Millisecond)
		f.send(f.answer(3600, "fe80::62"), ifCable)

		// then: the usable list never changed
		f.none()
	})

	t.Run("a cold split announcement resolves", func(t *testing.T) {
		// given: PTR and SRV first, nothing known yet
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600), ifCable)

		// when: the address in its own packet
		bare := new(dns.Msg)
		bare.Response = true
		bare.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::62")}}
		f.send(bare, ifCable)

		// then
		if got, want := addrStrings(f.next()), []string{"fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an address beside a PTR without SRV reaches the entry", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when
		msg := f.answer(3600, "fe80::62")
		msg.Extra = msg.Extra[1:] // drop the SRV
		f.send(msg, ifCable)

		// then
		if got, want := addrStrings(f.next()), []string{"192.168.1.62", "fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an answer without cache-flush adds to the link", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "fe80::1"), ifCable)
		f.next()

		// when
		f.send(f.answer(3600, "fe80::2"), ifCable)

		// then
		if got, want := addrStrings(f.next()), []string{"fe80::1%if31", "fe80::2%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a goodbye for one address keeps the others", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()
		f.send(f.answer(3600, "fe80::62", "2001:db8::61"), ifCable)
		f.next()

		// when
		f.send(f.answerTTL(3600, 0, "2001:db8::61"), ifCable)

		// then: the global address was never usable, so nothing changed
		f.none()
		f.send(f.answerTTL(3600, 0, "fe80::62"), ifCable)
		if got, want := addrStrings(f.next()), []string{"192.168.1.62"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("addresses sent apart from the service records reach the entry", func(t *testing.T) {
		// given: resolved over Wi-Fi
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when: the cable carries a bare AAAA for the same target
		bare := new(dns.Msg)
		bare.Response = true
		bare.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::62")}}
		f.send(bare, ifCable)

		// then
		e := f.next()
		if got, want := addrStrings(e), []string{"192.168.1.62", "fe80::62%if31"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
		if e.Port != 4006 || e.Instance != "peer1" {
			t.Errorf("entry = %s:%d, want peer1:4006", e.Instance, e.Port)
		}
	})

	t.Run("AAAA changes on an IPv4 link deliver nothing new", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62", "2a0d::1"), ifWifi)
		f.next()

		// when
		f.send(f.answer(3600, "192.168.1.62", "2a0d::2", "fe80::9"), ifWifi)
		f.send(f.answer(3600, "192.168.1.62"), 5)

		// then
		f.none()
	})

	t.Run("without selected IPv6 links the first answer is final", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, &client{}, true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when
		f.send(f.answer(3600, "192.168.1.63"), 5)
		f.send(f.answer(3600, "fe80::62"), ifCable)

		// then
		f.none()
	})
}

func TestLookupReturnsAfterItsFirstResult(t *testing.T) {
	// given: a lookup with an unbuffered channel and two different answers
	f := newMainloopFixture(t, cableClient(), false, 0)
	f.send(f.answer(3600, "192.168.1.62"), ifWifi)
	f.send(f.answer(3600, "fe80::62"), ifCable)

	// when: the caller takes the first result and cancels
	f.next()
	time.Sleep(50 * time.Millisecond)
	f.cancel()

	// then
	select {
	case <-f.done:
	case <-time.After(time.Second):
		t.Fatal("mainloop did not return after cancellation")
	}
}

func TestRecvLoopDropsUnselectedInterfaces(t *testing.T) {
	// given
	m := new(dns.Msg)
	m.SetQuestion("_anytype._tcp.local.", dns.TypePTR)
	packet, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	from := []int{ifWifi, ifCable}
	readFrom := func(b []byte) (int, int, error) {
		if len(from) == 0 {
			<-ctx.Done()
			return 0, 0, net.ErrClosed
		}
		i := from[0]
		from = from[1:]
		return copy(b, packet), i, nil
	}
	msgCh := make(chan receivedMsg, 2)

	// when
	go recvLoop(ctx, readFrom, func(i int) bool { return i == ifCable }, msgCh)

	// then
	select {
	case got := <-msgCh:
		if got.ifIndex != ifCable {
			t.Errorf("delivered a packet from interface %d", got.ifIndex)
		}
	case <-time.After(time.Second):
		t.Fatal("the selected interface's packet was dropped")
	}
}

func TestRecvReportsTheReceivingInterface(t *testing.T) {
	lo := loopbackInterface(t)
	for _, tc := range []struct {
		network string
		ip      net.IP
		conn    func(*net.UDPConn) (interface{}, func() error, error)
	}{
		{"udp4", net.IPv4(127, 0, 0, 1), func(c *net.UDPConn) (interface{}, func() error, error) {
			p := ipv4.NewPacketConn(c)
			return p, p.Close, p.SetControlMessage(ipv4.FlagInterface, true)
		}},
		{"udp6", net.IPv6loopback, func(c *net.UDPConn) (interface{}, func() error, error) {
			p := ipv6.NewPacketConn(c)
			return p, p.Close, p.SetControlMessage(ipv6.FlagInterface, true)
		}},
	} {
		t.Run(tc.network, func(t *testing.T) {
			// given: a real socket with control messages, as the client sets it up
			conn, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: tc.ip})
			if err != nil {
				t.Skipf("no %s loopback: %v", tc.network, err)
			}
			pConn, closeConn, err := tc.conn(conn)
			if err != nil {
				t.Skipf("no control messages here: %v", err)
			}
			defer closeConn()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			msgCh := make(chan receivedMsg, 1)
			go (&client{}).recv(ctx, pConn, msgCh)

			// when
			m := new(dns.Msg)
			m.SetQuestion("_anytype._tcp.local.", dns.TypePTR)
			packet, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			sender, err := net.DialUDP(tc.network, nil, conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			if _, err := sender.Write(packet); err != nil {
				t.Fatal(err)
			}

			// then
			select {
			case got := <-msgCh:
				if got.ifIndex != lo.Index {
					t.Errorf("ifIndex = %d, want the loopback interface %d", got.ifIndex, lo.Index)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no packet received")
			}
		})
	}
}

func loopbackInterface(t *testing.T) net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface
		}
	}
	t.Skip("no loopback interface")
	return net.Interface{}
}

func TestJoinUdp6MulticastOnlySelected(t *testing.T) {
	// given: every multicast interface, but IPv6 selected on none / on one
	list := NewInterfaceList(listMulticastInterfaces())
	if len(list) == 0 {
		t.Skip("no multicast interfaces")
	}

	// when: nothing selected
	_, err := joinUdp6Multicast(list, map[int]struct{}{})

	// then
	if err == nil {
		t.Fatal("joined IPv6 with no interface selected")
	}
	for _, iface := range list {
		if iface.HasFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined) {
			t.Errorf("%s joined although not selected", iface.Name)
		}
	}
}

func TestEnumerationIgnoresIPv6Selection(t *testing.T) {
	// given: a service type enumeration with IPv6 interfaces selected
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	params := defaultParams("_services._dns-sd._udp")
	entries := make(chan *ServiceEntry, 1)
	params.Entries = entries
	params.isBrowsing = true
	msgCh := make(chan receivedMsg, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		cableClient().mainloop(ctx, params, msgCh)
	}()

	// when
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "_anytype._tcp.local."}}
	msgCh <- receivedMsg{msg: msg, ifIndex: ifCable}

	// then
	select {
	case <-entries:
	case <-ctx.Done():
		t.Fatal("the enumeration result was not delivered")
	}
	cancel()
	<-done
}
