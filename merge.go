package zeroconf

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
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
	seen  time.Time // when the record last arrived
}

// answerAddrs are the address records one message carried for one instance.
// flush4/flush6 say a record of that family had the cache-flush bit: the
// sender lists its complete set, which replaces what the link had.
type answerAddrs struct {
	v4, v6         []addrRecord
	flush4, flush6 bool
}

// maxIPv6TTL caps how long an AAAA record stays live without being heard
// again. Bonjour announces 4500 s, but a link-local address on a link the
// peer has left (without a goodbye) would be dialed first for that long; the
// browser asks at least once a minute and peers answer every query, so a
// live address keeps being renewed. 120 s is the address TTL RFC 6762 10
// recommends and our responder uses.
const maxIPv6TTL = 120 * time.Second

func (a *answerAddrs) add(ip net.IP, ifIndex int, hdr dns.RR_Header, now time.Time) {
	ttl := time.Duration(hdr.Ttl) * time.Second
	if ip.To4() == nil && ttl > maxIPv6TTL {
		ttl = maxIPv6TTL
	}
	rec := addrRecord{ip: ip, exp: now.Add(ttl), seen: now}
	flush := hdr.Class&qClassCacheFlush != 0
	if ip.To4() != nil {
		a.v4 = append(a.v4, rec)
		a.flush4 = a.flush4 || flush
		return
	}
	if zoned, ok := zonedIPv6(ip, ifIndex); ok {
		rec.zoned = zoned
	}
	a.v6 = append(a.v6, rec)
	a.flush6 = a.flush6 || flush
}

// mergeRecords applies records to a link's family. Each record renews, adds
// or (TTL 0) withdraws its own address. A live record with the cache-flush
// bit also says the sender's set is complete, so the link's other addresses
// expire one second later, unless they arrived within the last second
// themselves: a set split over several packets must survive (RFC 6762 10.2).
func mergeRecords(have, records []addrRecord, flush bool, now time.Time) []addrRecord {
	res := slices.Clone(have)
	if flush && slices.ContainsFunc(records, func(r addrRecord) bool { return r.exp.After(now) }) {
		deadline := now.Add(time.Second)
		for i, h := range res {
			listed := slices.ContainsFunc(records, func(r addrRecord) bool { return r.ip.Equal(h.ip) })
			if !listed && now.Sub(h.seen) >= time.Second && h.exp.After(deadline) {
				res[i].exp = deadline
			}
		}
	}
	for _, r := range records {
		if i := slices.IndexFunc(res, func(h addrRecord) bool { return h.ip.Equal(r.ip) }); i >= 0 {
			res[i] = r
		} else {
			res = append(res, r)
		}
	}
	return res
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
	tmpl      *ServiceEntry // the instance's service record, see template
	// serviceLinks are the links whose service records are live: after
	// the last one says goodbye, an address record alone (the host may
	// still answer for other services) must not revive the instance
	serviceLinks map[int]struct{}
	// withdrawn are the links whose service said goodbye: an address
	// record alone does not bring the link back, fresh service records do
	withdrawn map[int]struct{}
	cached    *ServiceEntry // the last entry template handed out
	// linkLocal says the instance had a usable link-local address on a
	// selected interface: only such an instance is delivered again when
	// its addresses change. Any other keeps the first answer, as without
	// selected interfaces, so a cable elsewhere changes nothing for it.
	linkLocal bool
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
		delete(inst.serviceLinks, ifIndex)
		if inst.withdrawn == nil {
			inst.withdrawn = map[int]struct{}{}
		}
		inst.withdrawn[ifIndex] = struct{}{}
		return
	}
	if fresh != inst.cached {
		// service records of this packet, not a template of ours
		if inst.serviceLinks == nil {
			inst.serviceLinks = map[int]struct{}{}
		}
		inst.serviceLinks[ifIndex] = struct{}{}
		delete(inst.withdrawn, ifIndex)
	}
	inst.expiry = fresh.Expiry
	if inst.tmpl == nil {
		tmpl := *fresh
		tmpl.AddrIPv4, tmpl.AddrIPv6, tmpl.AddrIPv6Zoned = nil, nil, nil
		inst.tmpl = &tmpl
	}
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
	link.v4 = mergeRecords(link.v4, addrs.v4, addrs.flush4, now)
	link.v6 = mergeRecords(link.v6, addrs.v6, addrs.flush6, now)
}

// target is the host an entry's address records belong to: the packet's own
// SRV target, or for a partial entry (PTR or TXT without SRV) the instance's
// resolved one. The entry itself is left as the packet made it.
func (m ifaceAddrs) target(key string, e *ServiceEntry, now time.Time) string {
	if e.HostName != "" {
		return e.HostName
	}
	inst := m[key]
	if inst == nil || inst.port == 0 || !inst.expiry.After(now) || len(inst.serviceLinks) == 0 {
		return ""
	}
	return inst.host
}

// template returns an entry for an instance whose target is hostName, to
// carry address records that arrived without the service records (a split
// announcement, a renewal of the address alone); nil when none is known.
func (m ifaceAddrs) template(key, hostName string, ifIndex int, now time.Time) *ServiceEntry {
	inst := m[key]
	if inst == nil || inst.tmpl == nil || inst.host != hostName || !inst.expiry.After(now) || len(inst.serviceLinks) == 0 {
		return nil
	}
	if _, gone := inst.withdrawn[ifIndex]; gone {
		return nil
	}
	e := *inst.tmpl
	e.HostName, e.Port, e.Text, e.Expiry = inst.host, inst.port, inst.text, inst.expiry
	e.AddrIPv4, e.AddrIPv6, e.AddrIPv6Zoned = nil, nil, nil
	inst.cached = &e
	return &e
}

// prune drops expired records and empty links, and an instance with no link
// left once its service records expired too (a split announcement resolves
// the target before its addresses arrive).
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
		if len(inst.links) == 0 && !inst.expiry.After(now) {
			delete(m, key)
		}
	}
}

// cachedTemplate is the last entry template handed out for the instance, to
// tell it from an entry built from a packet's own service records.
func (m ifaceAddrs) cachedTemplate(key string) *ServiceEntry {
	if inst := m[key]; inst != nil {
		return inst.cached
	}
	return nil
}

// usesLinkLocal reports whether the instance is delivered again on change,
// see instanceAddrs.linkLocal.
func (m ifaceAddrs) usesLinkLocal(key string) bool {
	inst := m[key]
	return inst != nil && inst.linkLocal
}

// currentKey is the delivery key the instance has now from its cache alone
// (see entry), or "" when nothing is deliverable. A delivered key that no
// longer matches means some of what was delivered expired: a peer coming
// back unchanged is news then.
func (m ifaceAddrs) currentKey(key string, now time.Time, selected map[int]struct{}) string {
	inst := m[key]
	if inst == nil || inst.tmpl == nil {
		return ""
	}
	_, k, ok := m.entry(key, inst.tmpl, now, selected)
	if !ok {
		return ""
	}
	return k
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
				inst.linkLocal = true
			}
		}
	}
	if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
		return nil, "", false
	}
	slices.Sort(usable)
	return &e, inst.host + ":" + strconv.Itoa(inst.port) + "|" + strings.Join(usable, ","), true
}
