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
