package zeroconf

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A browser selected IPv6 interfaces (SelectIPv6Ifaces) for a link that has
// no IPv4, so one peer may answer on several links: IPv4 over Wi-Fi, IPv6
// link-local over a cable. ifaceAddrs keeps what each link last said so a
// later answer can change an entry that was already delivered. Without
// selected interfaces the first answer is final, as it always was.

// addrRecord is one A or AAAA record, live until exp (its own TTL; a goodbye
// with TTL 0 is never live). zoned is set for an AAAA record when it can be
// dialed (see zonedIPv6).
type addrRecord struct {
	ip    net.IP
	zoned netip.Addr
	exp   time.Time
}

// answerAddrs are the address records one message carried for one instance.
type answerAddrs struct {
	v4, v6 []addrRecord
}

func (a *answerAddrs) add(ip net.IP, ifIndex int, ttl uint32, now time.Time) {
	rec := addrRecord{ip: ip, exp: now.Add(time.Duration(ttl) * time.Second)}
	if ip.To4() != nil {
		a.v4 = append(a.v4, rec)
		return
	}
	if zoned, ok := zonedIPv6(ip, ifIndex); ok {
		rec.zoned = zoned
	}
	a.v6 = append(a.v6, rec)
}

// linkAddrs is what one interface last told us about one instance, per
// family: an answer carrying a family replaces it (cache-flush style), so an
// address the peer dropped goes with it, and an answer on another link never
// renews it.
type linkAddrs struct {
	v4, v6 []addrRecord
	order  int
}

// instanceAddrs is one instance across links, with the last resolved
// service target: a partial answer (PTR or TXT only) keeps the known one.
type instanceAddrs struct {
	links     map[int]*linkAddrs
	nextOrder int
	host      string
	port      int
	text      []string
	expiry    time.Time
}

type ifaceAddrs map[string]*instanceAddrs

// update records fresh, received on ifIndex with the address records addrs.
// A service goodbye (fresh expired) withdraws this link only.
func (m ifaceAddrs) update(key string, ifIndex int, fresh *ServiceEntry, addrs *answerAddrs, now time.Time) {
	inst := m[key]
	if inst == nil {
		inst = &instanceAddrs{links: map[int]*linkAddrs{}}
		m[key] = inst
	}
	if !fresh.Expiry.After(now) {
		delete(inst.links, ifIndex)
		return
	}
	inst.expiry = fresh.Expiry
	if fresh.Port != 0 && fresh.HostName != "" {
		inst.host, inst.port = fresh.HostName, fresh.Port
	}
	if fresh.Text != nil {
		inst.text = fresh.Text
	}
	if addrs == nil {
		return
	}
	link := inst.links[ifIndex]
	if link == nil {
		link = &linkAddrs{order: inst.nextOrder}
		inst.nextOrder++
		inst.links[ifIndex] = link
	}
	if len(addrs.v4) > 0 {
		link.v4 = addrs.v4
	}
	if len(addrs.v6) > 0 {
		link.v6 = addrs.v6
	}
}

// prune drops expired records, empty links and instances with no link left.
func (m ifaceAddrs) prune(now time.Time) {
	live := func(r addrRecord) bool { return !r.exp.After(now) }
	for key, inst := range m {
		for i, link := range inst.links {
			link.v4 = slices.DeleteFunc(link.v4, live)
			link.v6 = slices.DeleteFunc(link.v6, live)
			if len(link.v4) == 0 && len(link.v6) == 0 {
				delete(inst.links, i)
			}
		}
		if len(inst.links) == 0 {
			delete(m, key)
		}
	}
}

// entry returns the instance as one entry: the last resolved target with the
// live addresses of every link, in the order the links first answered. ok is
// false while there is nothing to deliver (no resolved target, no address).
// The key decides whether a delivery is due: the target, the IPv4 addresses
// and the link-local addresses received on a selected interface (selected),
// the only ones a caller can use beyond the first answer.
func (m ifaceAddrs) entry(key string, fresh *ServiceEntry, now time.Time, selected map[int]struct{}) (merged *ServiceEntry, deliveryKey string, ok bool) {
	m.prune(now)
	inst := m[key]
	if inst == nil || inst.port == 0 {
		return nil, "", false
	}
	indexes := make([]int, 0, len(inst.links))
	for i := range inst.links {
		indexes = append(indexes, i)
	}
	slices.SortFunc(indexes, func(a, b int) int { return inst.links[a].order - inst.links[b].order })

	e := *fresh
	e.HostName, e.Port, e.Text, e.Expiry = inst.host, inst.port, inst.text, inst.expiry
	e.AddrIPv4, e.AddrIPv6, e.AddrIPv6Zoned = nil, nil, nil
	var usable []string
	for _, i := range indexes {
		link := inst.links[i]
		for _, r := range link.v4 {
			if !slices.ContainsFunc(e.AddrIPv4, r.ip.Equal) {
				e.AddrIPv4 = append(e.AddrIPv4, r.ip)
				usable = append(usable, r.ip.String())
			}
		}
		_, sel := selected[i]
		for _, r := range link.v6 {
			if !slices.ContainsFunc(e.AddrIPv6, r.ip.Equal) {
				e.AddrIPv6 = append(e.AddrIPv6, r.ip)
			}
			if !r.zoned.IsValid() || slices.Contains(e.AddrIPv6Zoned, r.zoned) {
				continue
			}
			e.AddrIPv6Zoned = append(e.AddrIPv6Zoned, r.zoned)
			if sel && r.zoned.Zone() != "" {
				usable = append(usable, r.zoned.String())
			}
		}
	}
	if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
		return nil, "", false
	}
	slices.Sort(usable)
	return &e, inst.host + ":" + strconv.Itoa(inst.port) + "|" + strings.Join(usable, ","), true
}
