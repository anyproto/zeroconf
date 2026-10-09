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

func TestMainloopMergesAddressesFromLaterAnswers(t *testing.T) {
	// given: the peer answers on Wi-Fi first, then over the cable
	const ifCable = 31
	orig := interfaceZone
	t.Cleanup(func() { interfaceZone = orig })
	interfaceZone = func(int) string { return "en16" }

	params := defaultParams("_anytype._tcp")
	instance := "peer1." + params.ServiceName()
	host := "peer1.local."
	answer := func(addr dns.RR) *dns.Msg {
		msg := new(dns.Msg)
		msg.Response = true
		msg.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: params.ServiceName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600}, Ptr: instance}}
		msg.Extra = []dns.RR{
			&dns.SRV{Hdr: dns.RR_Header{Name: instance, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 3600}, Port: 4006, Target: host},
			addr,
		}
		return msg
	}
	wifi := answer(&dns.A{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.168.1.62")})
	cable := answer(&dns.AAAA{Hdr: dns.RR_Header{Name: host, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120}, AAAA: net.ParseIP("fe80::62")})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	entries := make(chan *ServiceEntry, 4)
	params.Entries = entries
	params.isBrowsing = true
	msgCh := make(chan receivedMsg, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&client{}).mainloop(ctx, params, msgCh)
	}()
	next := func() *ServiceEntry {
		select {
		case e := <-entries:
			return e
		case <-ctx.Done():
			t.Fatal("no entry delivered")
			return nil
		}
	}

	// when
	msgCh <- receivedMsg{msg: wifi, ifIndex: 4}
	first := next()
	// the subscriber may reorder what it got (heart sorts AddrIPv4)
	first.AddrIPv4[0] = net.ParseIP("192.0.2.1")
	msgCh <- receivedMsg{msg: cable, ifIndex: ifCable}
	second := next()
	msgCh <- receivedMsg{msg: cable, ifIndex: ifCable}
	msgCh <- receivedMsg{msg: wifi, ifIndex: 4}

	// then
	if len(first.AddrIPv4) != 1 || len(first.AddrIPv6Zoned) != 0 {
		t.Errorf("first entry = %v %v, want the Wi-Fi address only", first.AddrIPv4, first.AddrIPv6Zoned)
	}
	if len(second.AddrIPv4) != 1 || !second.AddrIPv4[0].Equal(net.ParseIP("192.168.1.62")) || !reflect.DeepEqual(second.AddrIPv6Zoned, []netip.Addr{netip.MustParseAddr("fe80::62%en16")}) {
		t.Errorf("second entry = %v %v, want both addresses", second.AddrIPv4, second.AddrIPv6Zoned)
	}
	if len(first.AddrIPv6Zoned) != 0 {
		t.Error("the delivered first entry was modified")
	}
	select {
	case e := <-entries:
		t.Errorf("repeated answers re-delivered %v", e)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	<-done
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
