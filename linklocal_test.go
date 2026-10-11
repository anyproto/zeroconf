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
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: f.params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}, Ptr: f.instance}}
	msg.Extra = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: f.instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}, Port: 4006, Target: f.host}}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip.To4() != nil {
			msg.Extra = append(msg.Extra, &dns.A{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: ip})
		} else {
			msg.Extra = append(msg.Extra, &dns.AAAA{Hdr: dns.RR_Header{Name: f.host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: ip})
		}
	}
	return msg
}

// send feeds a packet from the IPv4 socket, send6 one from the IPv6 socket.
func (f *mainloopFixture) send(msg *dns.Msg, ifIndex int) {
	f.msgCh <- receivedMsg{msg: msg, ifIndex: ifIndex}
}

func (f *mainloopFixture) send6(msg *dns.Msg, ifIndex int) {
	f.msgCh <- receivedMsg{msg: msg, ifIndex: ifIndex, v6: true}
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
		f.t.Errorf("unexpected delivery: %v %v on link %d", e.AddrIPv4, e.AddrIPv6Zoned, e.LinkIndex)
	case <-time.After(100 * time.Millisecond):
	}
}

const (
	ifWifi   = 4
	ifCable  = 31
	ifCable2 = 32
)

func cableClient() *client {
	return &client{ipv6Ifaces: indexSet([]int{ifCable})}
}

func TestMainloopDeliversEachCableSeparately(t *testing.T) {
	t.Run("a Wi-Fi answer then a cable answer are two deliveries", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		first := f.next()

		// when
		f.send6(f.answer(3600, "fe80::1"), ifCable)

		// then
		second := f.next()
		if first.LinkIndex != 0 {
			t.Errorf("Wi-Fi entry LinkIndex = %d, want 0", first.LinkIndex)
		}
		if second.LinkIndex != ifCable {
			t.Errorf("cable entry LinkIndex = %d, want %d", second.LinkIndex, ifCable)
		}
		if want := []netip.Addr{netip.MustParseAddr("fe80::1%if31")}; !reflect.DeepEqual(second.AddrIPv6Zoned, want) {
			t.Errorf("cable entry AddrIPv6Zoned = %v, want %v", second.AddrIPv6Zoned, want)
		}
	})

	t.Run("a cable answer then a Wi-Fi answer are two deliveries", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send6(f.answer(3600, "fe80::1"), ifCable)
		f.next()

		// when
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then
		if e := f.next(); e.LinkIndex != 0 {
			t.Errorf("Wi-Fi entry LinkIndex = %d, want 0", e.LinkIndex)
		}
	})

	t.Run("IPv4 socket answers keep the once-per-TTL dedup with a cable selected", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()

		// when: changed addresses, and the IPv4 socket hearing it on the cable
		f.send(f.answer(3600, "192.168.1.63"), ifWifi)
		f.send(f.answer(3600, "192.168.1.62"), ifCable)

		// then
		f.none()
	})

	t.Run("a repeated cable answer is delivered once until the redelivery cap", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send6(f.answer(3600, "fe80::1"), ifCable)
		e := f.next()

		// when
		f.send6(f.answer(3600, "fe80::1"), ifCable)

		// then
		if d := time.Until(e.Expiry) - linkRedelivery; d < -2*time.Second || d > 2*time.Second {
			t.Errorf("expires in %v, want %v", time.Until(e.Expiry), linkRedelivery)
		}
		f.none()
	})

	t.Run("a shorter service TTL is kept", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)

		// when
		f.send6(f.answer(60, "fe80::1"), ifCable)

		// then
		if e := f.next(); time.Until(e.Expiry) > time.Minute {
			t.Errorf("expires in %v, want its own 60 s", time.Until(e.Expiry))
		}
	})

	t.Run("a cable answer is delivered again once the cap expired", func(t *testing.T) {
		// given
		origCleanup, origCap := cleanupFreq, linkRedelivery
		cleanupFreq, linkRedelivery = 50*time.Millisecond, 100*time.Millisecond
		t.Cleanup(func() { cleanupFreq, linkRedelivery = origCleanup, origCap })
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send6(f.answer(3600, "fe80::1"), ifCable)
		f.next()
		time.Sleep(300 * time.Millisecond) // past the cap plus a cleanup tick

		// when
		f.send6(f.answer(3600, "fe80::1"), ifCable)

		// then
		if e := f.next(); e.LinkIndex != ifCable {
			t.Errorf("LinkIndex = %d, want %d", e.LinkIndex, ifCable)
		}
	})

	t.Run("a cable goodbye frees only that link", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.next()
		f.send6(f.answer(3600, "fe80::1"), ifCable)
		f.next()

		// when
		f.send6(f.answer(0), ifCable)
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)
		f.send6(f.answer(3600, "fe80::1"), ifCable)

		// then
		if e := f.next(); e.LinkIndex != ifCable {
			t.Errorf("LinkIndex = %d, want %d", e.LinkIndex, ifCable)
		}
		f.none()
	})

	t.Run("two cables are independent", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, &client{ipv6Ifaces: indexSet([]int{ifCable, ifCable2})}, true, 4)

		// when
		f.send6(f.answer(3600, "fe80::1"), ifCable)
		f.send6(f.answer(3600, "fe80::2"), ifCable2)

		// then
		if got, want := []int{f.next().LinkIndex, f.next().LinkIndex}, []int{ifCable, ifCable2}; !reflect.DeepEqual(got, want) {
			t.Errorf("LinkIndex = %v, want %v", got, want)
		}
	})

	t.Run("without a selection IPv6 packets use the instance key", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, &client{}, true, 4)
		f.send6(f.answer(3600, "2a0d::5"), ifWifi)
		if e := f.next(); e.LinkIndex != 0 {
			t.Errorf("LinkIndex = %d, want 0", e.LinkIndex)
		}

		// when
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then
		f.none()
	})

	t.Run("IPv6 packets on an unselected interface use the instance key", func(t *testing.T) {
		// given
		f := newMainloopFixture(t, cableClient(), true, 4)
		f.send6(f.answer(3600, "2a0d::5"), ifWifi)
		if e := f.next(); e.LinkIndex != 0 {
			t.Errorf("LinkIndex = %d, want 0", e.LinkIndex)
		}

		// when
		f.send(f.answer(3600, "192.168.1.62"), ifWifi)

		// then
		f.none()
	})
}

func TestLinkLocalServerOptionLimitsIPv6ToItsInterfaces(t *testing.T) {
	// when
	opts := applyServerOpts(ServerLinkLocalIPv6(ifCable, ifCable2))

	// then: answers there carry their own link-local, and IPv6 goes nowhere else
	want := indexSet([]int{ifCable, ifCable2})
	if !reflect.DeepEqual(opts.linkLocalIfaces, want) {
		t.Errorf("link-local interfaces = %v, want %v", opts.linkLocalIfaces, want)
	}
	if !reflect.DeepEqual(opts.ipv6Ifaces, want) {
		t.Errorf("IPv6 interfaces = %v, want %v", opts.ipv6Ifaces, want)
	}
}

func TestIPv4OnlyBrowsingKeepsDeliveriesAcrossCleanup(t *testing.T) {
	// given: no IPv6 selection, a delivered peer, a cleanup tick
	origCleanup := cleanupFreq
	cleanupFreq = 100 * time.Millisecond
	t.Cleanup(func() { cleanupFreq = origCleanup })
	f := newMainloopFixture(t, &client{}, true, 4)
	f.send(f.answer(3600, "192.168.1.62"), ifWifi)
	f.next()
	time.Sleep(300 * time.Millisecond)

	// when: the same answer again, its service TTL far from expiry
	f.send(f.answer(3600, "192.168.1.62"), ifWifi)

	// then
	f.none()
}

func TestLookupReturnsAfterItsFirstResult(t *testing.T) {
	// given: a lookup with an unbuffered channel and two deliveries due, one
	// per link
	f := newMainloopFixture(t, cableClient(), false, 0)
	f.send(f.answer(3600, "192.168.1.62"), ifWifi)
	f.send6(f.answer(3600, "fe80::62"), ifCable)

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
	go recvLoop(ctx, readFrom, true, func(i int) bool { return i == ifCable }, msgCh)

	// then
	select {
	case got := <-msgCh:
		if got.ifIndex != ifCable {
			t.Errorf("delivered a packet from interface %d", got.ifIndex)
		}
		if !got.v6 {
			t.Error("the packet lost its IPv6 socket")
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
		v6      bool
	}{
		{"udp4", net.IPv4(127, 0, 0, 1), func(c *net.UDPConn) (interface{}, func() error, error) {
			p := ipv4.NewPacketConn(c)
			return p, p.Close, p.SetControlMessage(ipv4.FlagInterface, true)
		}, false},
		{"udp6", net.IPv6loopback, func(c *net.UDPConn) (interface{}, func() error, error) {
			p := ipv6.NewPacketConn(c)
			return p, p.Close, p.SetControlMessage(ipv6.FlagInterface, true)
		}, true},
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
				if got.v6 != tc.v6 {
					t.Errorf("v6 = %v, want %v", got.v6, tc.v6)
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
	ifaces := listMulticastInterfaces()

	t.Run("nothing selected joins nothing", func(t *testing.T) {
		list := NewInterfaceList(ifaces)
		if len(list) == 0 {
			t.Skip("no multicast interfaces")
		}

		_, err := joinUdp6Multicast(list, map[int]struct{}{})

		if err == nil {
			t.Fatal("joined IPv6 with no interface selected")
		}
		for _, iface := range list {
			if iface.HasFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined) {
				t.Errorf("%s joined although not selected", iface.Name)
			}
		}
	})

	t.Run("one selected joins only that one", func(t *testing.T) {
		// given: the first interface IPv6 can join, out of several
		list := NewInterfaceList(ifaces)
		if len(list) < 2 {
			t.Skip("needs two multicast interfaces")
		}
		probe, err := joinUdp6Multicast(NewInterfaceList(ifaces), nil)
		if err != nil {
			t.Skipf("no IPv6 multicast here: %v", err)
		}
		probe.Close()
		var selected int
		for _, iface := range list {
			if c, err := joinUdp6Multicast(NewInterfaceList([]net.Interface{iface.Interface}), nil); err == nil {
				c.Close()
				selected = iface.Index
				break
			}
		}

		// when
		conn, err := joinUdp6Multicast(list, map[int]struct{}{selected: {}})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		// then
		for _, iface := range list {
			joined := iface.HasFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined)
			if joined != (iface.Index == selected) {
				t.Errorf("%s joined=%v, selected=%v", iface.Name, joined, iface.Index == selected)
			}
		}
	})
}

func TestEnumerationIgnoresIPv6Selection(t *testing.T) {
	// given: a service type enumeration with IPv6 interfaces selected
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	params := defaultParams("_services._dns-sd._udp")
	entries := make(chan *ServiceEntry, 2)
	params.Entries = entries
	params.isBrowsing = true
	msgCh := make(chan receivedMsg, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		cableClient().mainloop(ctx, params, msgCh)
	}()

	// when: the same type over the cable's IPv6 socket, then over IPv4
	msg := new(dns.Msg)
	msg.Response = true
	msg.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "_anytype._tcp.local."}}
	msgCh <- receivedMsg{msg: msg, ifIndex: ifCable, v6: true}
	msgCh <- receivedMsg{msg: msg, ifIndex: ifWifi}

	// then: delivered once, for no link
	select {
	case e := <-entries:
		if e.LinkIndex != 0 {
			t.Errorf("LinkIndex = %d, want 0", e.LinkIndex)
		}
	case <-ctx.Done():
		t.Fatal("the enumeration result was not delivered")
	}
	select {
	case e := <-entries:
		t.Errorf("delivered again, on link %d", e.LinkIndex)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	<-done
}

func TestInterfaceZoneIsTheIndex(t *testing.T) {
	// a name would be resolved again at dial time, possibly to an old index
	if got := interfaceZone(31); got != "31" {
		t.Errorf("zone = %q, want the decimal index", got)
	}
}
