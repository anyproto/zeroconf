package zeroconf

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// A browser selected IPv6 interfaces (SelectIPv6Ifaces) for a link that has
// no IPv4, so one peer may answer on several links: IPv4 over Wi-Fi, IPv6
// link-local over a cable. ifaceAddrs keeps each link's latest addresses so a
// later answer can extend an entry that was already delivered. Without
// selected interfaces the first answer is final, as it always was.

// linkAddrs is what one interface last told us about one service instance,
// per family. A newer answer on the same interface replaces a family it
// carries, so an address the peer dropped goes with it; each family expires
// on its own, so an answer on another link never renews it.
type linkAddrs struct {
	v4, v6     []net.IP
	zoned      []netip.Addr
	v4Exp      time.Time
	v6Exp      time.Time
	firstOrder int
}

// ifaceAddrs maps instance -> interface index -> addresses.
type ifaceAddrs map[string]map[int]*linkAddrs

// update records the addresses of fresh, received on ifIndex.
func (m ifaceAddrs) update(key string, ifIndex int, fresh *ServiceEntry) {
	links := m[key]
	if links == nil {
		links = map[int]*linkAddrs{}
		m[key] = links
	}
	link := links[ifIndex]
	if link == nil {
		link = &linkAddrs{firstOrder: len(links)}
		links[ifIndex] = link
	}
	if len(fresh.AddrIPv4) > 0 {
		link.v4, link.v4Exp = slices.Clone(fresh.AddrIPv4), fresh.Expiry
	}
	if len(fresh.AddrIPv6) > 0 {
		link.v6, link.zoned, link.v6Exp = slices.Clone(fresh.AddrIPv6), slices.Clone(fresh.AddrIPv6Zoned), fresh.Expiry
	}
}

// entry returns fresh carrying the live addresses of every interface, in the
// order the interfaces first answered, and the key that decides whether a
// delivery is due: the IPv4 addresses and the link-local addresses received
// on a selected interface (selected), the only ones a caller can use beyond
// the first answer.
func (m ifaceAddrs) entry(key string, fresh *ServiceEntry, now time.Time, selected map[int]struct{}) (*ServiceEntry, string) {
	links := m[key]
	indexes := make([]int, 0, len(links))
	for i := range links {
		indexes = append(indexes, i)
	}
	slices.SortFunc(indexes, func(a, b int) int { return links[a].firstOrder - links[b].firstOrder })

	merged := *fresh
	merged.AddrIPv4, merged.AddrIPv6, merged.AddrIPv6Zoned = nil, nil, nil
	var usable []string
	for _, i := range indexes {
		link := links[i]
		if link.v4Exp.After(now) {
			for _, ip := range link.v4 {
				if !slices.ContainsFunc(merged.AddrIPv4, ip.Equal) {
					merged.AddrIPv4 = append(merged.AddrIPv4, ip)
					usable = append(usable, ip.String())
				}
			}
		}
		if link.v6Exp.After(now) {
			for _, ip := range link.v6 {
				if !slices.ContainsFunc(merged.AddrIPv6, ip.Equal) {
					merged.AddrIPv6 = append(merged.AddrIPv6, ip)
				}
			}
			_, sel := selected[i]
			for _, a := range link.zoned {
				if slices.Contains(merged.AddrIPv6Zoned, a) {
					continue
				}
				merged.AddrIPv6Zoned = append(merged.AddrIPv6Zoned, a)
				if sel && a.Zone() != "" {
					usable = append(usable, a.String())
				}
			}
		}
	}
	slices.Sort(usable)
	return &merged, strings.Join(usable, ",")
}
