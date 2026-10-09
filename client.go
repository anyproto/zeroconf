package zeroconf

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// IPType specifies the IP traffic the client listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, often contain
// both DNS A and AAAA entries.
type IPType uint8

// Options for IPType.
const (
	IPv4        IPType = 0x01
	IPv6        IPType = 0x02
	IPv4AndIPv6        = IPv4 | IPv6 // default option
)

var (
	initialQueryInterval      = 4 * time.Second
	defaultClientWriteTimeout = 10 * time.Second
)

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type client struct {
	ipv4conn     *ipv4.PacketConn
	ipv6conn     *ipv6.PacketConn
	interfaces   NetInterfaceList
	ipv6Ifaces   map[int]struct{} // see SelectIPv6Ifaces; nil means all
	writeTimeout time.Duration
}

type clientOpts struct {
	listenOn     IPType
	ifaces       []net.Interface
	ipv6Ifaces   map[int]struct{}
	writeTimeout time.Duration
}

// ClientOption fills the option struct to configure intefaces, etc.
type ClientOption func(*clientOpts)

// SelectIPTraffic selects the type of IP packets (IPv4, IPv6, or both) this
// instance listens for.
// This does not guarantee that only mDNS entries of this sepcific
// type passes. E.g. typical mDNS packets distributed via IPv4, may contain
// both DNS A and AAAA entries.
func SelectIPTraffic(t IPType) ClientOption {
	return func(o *clientOpts) {
		o.listenOn = t
	}
}

// SelectIfaces selects the interfaces to query for mDNS records
func SelectIfaces(ifaces []net.Interface) ClientOption {
	return func(o *clientOpts) {
		o.ifaces = ifaces
	}
}

// SelectIPv6Ifaces limits IPv6 traffic to the interfaces with these indexes,
// out of those selected by SelectIfaces: IPv4 keeps using all of them. It also
// makes a browser deliver an entry again when an answer on another interface
// changes its IPv4 addresses or its link-local addresses on these interfaces
// (see ifaceAddrs); otherwise an entry is delivered once per TTL.
func SelectIPv6Ifaces(ifIndexes ...int) ClientOption {
	return func(o *clientOpts) {
		o.ipv6Ifaces = indexSet(ifIndexes)
	}
}

func indexSet(ifIndexes []int) map[int]struct{} {
	set := make(map[int]struct{}, len(ifIndexes))
	for _, i := range ifIndexes {
		set[i] = struct{}{}
	}
	return set
}

// ClientWriteTimeout sets timeout for writing to the socket
func ClientWriteTimeout(duration time.Duration) ClientOption {
	return func(o *clientOpts) {
		o.writeTimeout = duration
	}
}

// Browse for all services of a given type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
// The entries channel is closed on every return path, so consumers may safely
// range over it.
func Browse(ctx context.Context, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		close(entries)
		return err
	}
	params := defaultParams(service)
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	params.isBrowsing = true
	return cl.run(ctx, params)
}

// Lookup a specific service by its name and type in a given domain.
// Received entries are sent on the entries channel.
// It blocks until the context is canceled (or an error occurs).
// The entries channel is closed on every return path, so consumers may safely
// range over it.
func Lookup(ctx context.Context, instance, service, domain string, entries chan<- *ServiceEntry, opts ...ClientOption) error {
	cl, err := newClient(applyOpts(opts...))
	if err != nil {
		close(entries)
		return err
	}
	params := defaultParams(service)
	params.Instance = instance
	if domain != "" {
		params.Domain = domain
	}
	params.Entries = entries
	return cl.run(ctx, params)
}

func applyOpts(options ...ClientOption) clientOpts {
	// Apply default configuration and load supplied options.
	var conf = clientOpts{
		listenOn:     IPv4AndIPv6,
		writeTimeout: defaultClientWriteTimeout,
	}
	for _, o := range options {
		if o != nil {
			o(&conf)
		}
	}
	return conf
}

func (c *client) run(ctx context.Context, params *lookupParams) error {
	ctx, cancel := context.WithCancel(ctx)
	// start listening for responses
	msgCh := make(chan receivedMsg, 32)
	if c.ipv4conn != nil {
		go c.recv(ctx, c.ipv4conn, msgCh)
	}
	if c.ipv6conn != nil {
		go c.recv(ctx, c.ipv6conn, msgCh)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.mainloop(ctx, params, msgCh)
	}()

	// If previous probe was ok, it should be fine now. In case of an error later on,
	// the entries' queue is closed.
	err := c.periodicQuery(ctx, params)
	cancel()
	<-done
	return err
}

// defaultParams returns a default set of QueryParams.
func defaultParams(service string) *lookupParams {
	return newLookupParams("", service, "local", false, make(chan *ServiceEntry))
}

// Client structure constructor
func newClient(opts clientOpts) (*client, error) {
	ifaces := opts.ifaces
	if len(ifaces) == 0 {
		ifaces = listMulticastInterfaces()
	}
	ifaceList := NewInterfaceList(ifaces)
	// When both families are requested, one that cannot join (IPv6 disabled
	// on the host, say) must not take the other down with it.
	var err4, err6 error
	// IPv4 interfaces
	var ipv4conn *ipv4.PacketConn
	if (opts.listenOn & IPv4) > 0 {
		ipv4conn, err4 = joinUdp4Multicast(ifaceList)
	}
	// IPv6 interfaces
	var ipv6conn *ipv6.PacketConn
	if (opts.listenOn & IPv6) > 0 {
		ipv6conn, err6 = joinUdp6Multicast(ifaceList, opts.ipv6Ifaces)
	}
	if ipv4conn == nil && ipv6conn == nil {
		return nil, errors.Join(err4, err6)
	}

	return &client{
		ipv4conn:     ipv4conn,
		ipv6conn:     ipv6conn,
		interfaces:   ifaceList,
		ipv6Ifaces:   opts.ipv6Ifaces,
		writeTimeout: opts.writeTimeout,
	}, nil
}

var cleanupFreq = 10 * time.Second

// hasTarget reports whether an entry of this packet resolved to hostName.
func hasTarget(entries map[string]*ServiceEntry, hostName string) bool {
	for _, e := range entries {
		if e.HostName == hostName {
			return true
		}
	}
	return false
}

// receivedMsg is a decoded packet with the index of the interface it arrived
// on (0 when the platform does not report it).
type receivedMsg struct {
	msg     *dns.Msg
	ifIndex int
}

// interfaceZone names the interface a link-local address is reached through:
// its decimal index. A name would be resolved again at dial time through Go's
// interface cache, which can still map it to the old index for up to a
// minute after a cable is plugged back in. A var so tests can stub it.
var interfaceZone = func(ifIndex int) string {
	return strconv.Itoa(ifIndex)
}

// zonedIPv6 converts an AAAA address for ServiceEntry.AddrIPv6Zoned: a
// link-local one gets the receiving interface as its zone, and is dropped when
// that interface is unknown.
func zonedIPv6(ip net.IP, ifIndex int) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if !addr.IsLinkLocalUnicast() {
		return addr, true
	}
	if ifIndex <= 0 {
		return netip.Addr{}, false
	}
	return addr.WithZone(interfaceZone(ifIndex)), true
}

// Start listeners and waits for the shutdown signal from exit channel
func (c *client) mainloop(ctx context.Context, params *lookupParams, msgCh <-chan receivedMsg) {

	// Iterate through channels from listeners goroutines
	var entries map[string]*ServiceEntry
	sentEntries := make(map[string]*ServiceEntry)
	// not for service type enumeration, whose PTR-only results have no
	// target or address to merge
	merging := params.isBrowsing && len(c.ipv6Ifaces) > 0 &&
		params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName()
	byIface := ifaceAddrs{}
	sentKeys := map[string]string{}
	// send delivers e unless the context ends first: the subscriber may have
	// stopped reading (a lookup takes its first result and cancels)
	send := func(e *ServiceEntry) bool {
		select {
		case params.Entries <- e:
			return true
		case <-ctx.Done():
			params.done()
			c.shutdown()
			return false
		}
	}

	ticker := time.NewTicker(cleanupFreq)
	defer ticker.Stop()
	for {
		var (
			now     time.Time
			ifIndex int                     // interface the current message arrived on
			records map[string]*answerAddrs // its address records per instance
		)
		select {
		case <-ctx.Done():
			// Context expired. Notify subscriber that we are done here.
			params.done()
			c.shutdown()
			return
		case t := <-ticker.C:
			for k, e := range sentEntries {
				if t.After(e.Expiry) {
					delete(sentEntries, k)
					delete(sentKeys, k)
				}
			}
			// address records expire on their own TTLs, not on the
			// last delivery's
			byIface.prune(t)
			// an instance some of whose delivered addresses expired may
			// come back unchanged: forget its delivery so that is
			// delivered again
			if merging {
				for k, delivered := range sentKeys {
					if byIface.currentKey(k, t, c.ipv6Ifaces) != delivered {
						delete(sentEntries, k)
						delete(sentKeys, k)
					}
				}
			}
			continue
		case received := <-msgCh:
			msg := received.msg
			ifIndex = received.ifIndex
			now = time.Now()
			entries = make(map[string]*ServiceEntry)
			sections := append(msg.Answer, msg.Ns...)
			sections = append(sections, msg.Extra...)

			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.PTR:
					if params.ServiceName() != rr.Hdr.Name {
						continue
					}
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Ptr {
						continue
					}
					if _, ok := entries[rr.Ptr]; !ok {
						entries[rr.Ptr] = newServiceEntry(
							trimDot(strings.Replace(rr.Ptr, rr.Hdr.Name, "", -1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Ptr].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.SRV:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].HostName = rr.Target
					entries[rr.Hdr.Name].Port = int(rr.Port)
					entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				case *dns.TXT:
					if params.ServiceInstanceName() != "" && params.ServiceInstanceName() != rr.Hdr.Name {
						continue
					} else if !strings.HasSuffix(rr.Hdr.Name, params.ServiceName()) {
						continue
					}
					if _, ok := entries[rr.Hdr.Name]; !ok {
						entries[rr.Hdr.Name] = newServiceEntry(
							trimDot(strings.Replace(rr.Hdr.Name, params.ServiceName(), "", 1)),
							params.Service,
							params.Domain)
					}
					entries[rr.Hdr.Name].Text = rr.Txt
					entries[rr.Hdr.Name].Expiry = now.Add(time.Duration(rr.Hdr.Ttl) * time.Second)
				}
			}
			// Associate IPs in a second round as other fields should be filled by now.
			records = make(map[string]*answerAddrs)
			addRecord := func(k string, ip net.IP, hdr dns.RR_Header) {
				if records[k] == nil {
					records[k] = &answerAddrs{}
				}
				records[k].add(ip, ifIndex, hdr, now)
			}
			if merging {
				// address records without their service records in this
				// packet belong to the instances already resolved to
				// that target
				for _, answer := range sections {
					var name string
					switch rr := answer.(type) {
					case *dns.A:
						name = rr.Hdr.Name
					case *dns.AAAA:
						name = rr.Hdr.Name
					default:
						continue
					}
					if hasTarget(entries, name) {
						continue
					}
					for k := range byIface {
						if _, ok := entries[k]; ok {
							continue
						}
						if tmpl := byIface.template(k, name, ifIndex, now); tmpl != nil {
							entries[k] = tmpl
						}
					}
				}
			}
			// the merge cache matches address records to a partial entry's
			// resolved target too; the entry keeps only its own (see target)
			targets := make(map[string]string, len(entries))
			for k, e := range entries {
				targets[k] = e.HostName
				if merging {
					targets[k] = byIface.target(k, e, now)
				}
			}
			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv4 = append(entries[k].AddrIPv4, rr.A)
						}
						if targets[k] == rr.Hdr.Name {
							addRecord(k, rr.A, rr.Hdr)
						}
					}
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = append(entries[k].AddrIPv6, rr.AAAA)
							if zoned, ok := zonedIPv6(rr.AAAA, ifIndex); ok {
								entries[k].AddrIPv6Zoned = append(entries[k].AddrIPv6Zoned, zoned)
							}
						}
						if targets[k] == rr.Hdr.Name {
							addRecord(k, rr.AAAA, rr.Hdr)
						}
					}
				}
			}
		}

		if len(entries) > 0 {
			for k, e := range entries {
				var key string
				linkLocalPeer := false
				if merging {
					if delivered, sent := sentKeys[k]; sent && byIface.currentKey(k, now, c.ipv6Ifaces) != delivered {
						// some of what was delivered expired, or the cache
						// evicted the instance (the cleanup tick may not
						// have run yet): a peer coming back unchanged is news
						delete(sentEntries, k)
						delete(sentKeys, k)
					}
					fromPacket := e != byIface.cachedTemplate(k)
					byIface.update(k, ifIndex, e, records[k], now)
					merged, mergedKey, ok := byIface.entry(k, e, now, c.ipv6Ifaces)
					linkLocalPeer = ok && byIface.usesLinkLocal(k)
					if linkLocalPeer {
						if _, sent := sentEntries[k]; sent && mergedKey == sentKeys[k] {
							continue
						}
						e, key = merged, mergedKey
					} else {
						// never seen over a selected link: exactly as
						// without merging, on this packet's own entry; the
						// cache above only watches for a cable answer
						if !ok && byIface.usesLinkLocal(k) {
							// a cable peer with nothing left to dial
							delete(sentEntries, k)
							delete(sentKeys, k)
							continue
						}
						if !fromPacket {
							continue
						}
						if !e.Expiry.After(now) {
							delete(entries, k)
							delete(sentEntries, k)
							delete(sentKeys, k)
							continue
						}
						if _, sent := sentEntries[k]; sent {
							continue
						}
					}
				} else {
					if !e.Expiry.After(now) {
						delete(entries, k)
						delete(sentEntries, k)
						continue
					}
					if _, ok := sentEntries[k]; ok {
						continue
					}
				}

				// If this is an DNS-SD query do not throw PTR away.
				// It is expected to have only PTR for enumeration
				if params.ServiceRecord.ServiceTypeName() != params.ServiceRecord.ServiceName() {
					// Require at least one resolved IP address for ServiceEntry
					// TODO: wait some more time as chances are high both will arrive.
					if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
						continue
					}
				}
				// Submit entry to subscriber and cache it.
				// This is also a point to possibly stop probing actively for a
				// service entry.
				sentEntries[k] = e
				if linkLocalPeer {
					sentKeys[k] = key
				}
				if !send(e) {
					return
				}
				if !params.isBrowsing {
					params.disableProbing()
				}
			}
		}
	}
}

// Shutdown client will close currently open connections and channel implicitly.
func (c *client) shutdown() {
	if c.ipv4conn != nil {
		c.ipv4conn.Close()
	}
	if c.ipv6conn != nil {
		c.ipv6conn.Close()
	}
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *client) recv(ctx context.Context, l interface{}, msgCh chan<- receivedMsg) {
	var readFrom func([]byte) (n int, ifIndex int, err error)

	// the control message carries the receiving interface: a link-local
	// address in the answer is only reachable through it. It is nil where
	// the platform does not implement control messages (Windows).
	switch pConn := l.(type) {
	case *ipv6.PacketConn:
		readFrom = func(b []byte) (n int, ifIndex int, err error) {
			var cm *ipv6.ControlMessage
			n, cm, _, err = pConn.ReadFrom(b)
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			return
		}
	case *ipv4.PacketConn:
		readFrom = func(b []byte) (n int, ifIndex int, err error) {
			var cm *ipv4.ControlMessage
			n, cm, _, err = pConn.ReadFrom(b)
			if cm != nil {
				ifIndex = cm.IfIndex
			}
			return
		}

	default:
		return
	}

	var accept func(ifIndex int) bool
	if _, v6 := l.(*ipv6.PacketConn); v6 && c.ipv6Ifaces != nil {
		// the wildcard socket also takes unicast answers on other links
		accept = func(ifIndex int) bool {
			_, ok := c.ipv6Ifaces[ifIndex]
			return ok
		}
	}
	recvLoop(ctx, readFrom, accept, msgCh)
}

// recvLoop reads packets via readFrom, unpacks them into dns.Msg structures
// and forwards them to msgCh until ctx is canceled or the connection is
// closed. Transient read errors are retried with a growing backoff (see
// nextRecvBackoff), mirroring the server recv loops: a persistently erroring
// socket must neither busy-spin a core nor silently kill reception.
func recvLoop(ctx context.Context, readFrom func([]byte) (n int, ifIndex int, err error), accept func(ifIndex int) bool, msgCh chan<- receivedMsg) {
	buf := make([]byte, 65536)
	var backoff time.Duration
	for {
		if ctx.Err() != nil {
			return
		}

		n, ifIndex, err := readFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// The connection was closed (shutdown path): terminal.
				return
			}
			backoff = nextRecvBackoff(backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		if accept != nil && !accept(ifIndex) {
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			// log.Printf("[WARN] mdns: Failed to unpack packet: %v", err)
			continue
		}
		select {
		case msgCh <- receivedMsg{msg: msg, ifIndex: ifIndex}:
			// Submit decoded DNS message and continue.
		case <-ctx.Done():
			// Abort.
			return
		}
	}
}

// periodicQuery sens multiple probes until a valid response is received by
// the main processing loop or some timeout/cancel fires.
// TODO: move error reporting to shutdown function as periodicQuery is called from
// go routine context.
func (c *client) periodicQuery(ctx context.Context, params *lookupParams) error {
	// Do the first query immediately.
	if err := c.query(params); err != nil {
		return err
	}

	const maxInterval = 60 * time.Second
	interval := initialQueryInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			// Wait for next iteration.
		case <-params.stopProbing:
			// Chan is closed (or happened in the past).
			// Done here. Received a matching mDNS entry.
			return nil
		case <-ctx.Done():
			if params.isBrowsing {
				return nil
			}
			return ctx.Err()
		}

		if err := c.query(params); err != nil {
			return err
		}
		// Exponential increase of the interval with jitter:
		// the new interval will be between 1.5x and 2.5x the old interval, capped at maxInterval.
		if interval != maxInterval {
			interval += time.Duration(rand.Int63n(interval.Nanoseconds())) + interval/2
			if interval > maxInterval {
				interval = maxInterval
			}
		}
		timer.Reset(interval)
	}
}

// Performs the actual query by service name (browse) or service instance name (lookup),
// start response listeners goroutines and loops over the entries channel.
func (c *client) query(params *lookupParams) error {
	var serviceName, serviceInstanceName string
	serviceName = fmt.Sprintf("%s.%s.", trimDot(params.Service), trimDot(params.Domain))

	// send the query
	m := new(dns.Msg)
	if params.Instance != "" { // service instance name lookup
		serviceInstanceName = fmt.Sprintf("%s.%s", params.Instance, serviceName)
		m.Question = []dns.Question{
			{Name: serviceInstanceName, Qtype: dns.TypeSRV, Qclass: dns.ClassINET},
			{Name: serviceInstanceName, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
		}
	} else if len(params.Subtypes) > 0 { // service subtype browse
		m.SetQuestion(params.Subtypes[0], dns.TypePTR)
	} else { // service name browse
		m.SetQuestion(serviceName, dns.TypePTR)
	}
	m.RecursionDesired = false
	// only send multicast queries to interfaces that we have joined
	return c.sendQuery(m, NetInterfaceStateFlagMulticastJoined)
}

// Pack the dns.Msg and write to available connections (multicast)
func (c *client) sendQuery(msg *dns.Msg, requiredFlags ...NetInterfaceStateFlag) error {
	buf, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack msg %v: %w", msg, err)
	}
	if c.ipv4conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv4.ControlMessage
		for _, intf := range c.interfaces {
			if !intf.HasFlags(NetInterfaceScopeIPv4, requiredFlags...) {
				continue
			}
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = intf.Index
			default:
				if err := c.ipv4conn.SetMulticastInterface(&intf.Interface); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			setDeadline(c.writeTimeout, c.ipv4conn)
			n, err := c.ipv4conn.WriteTo(buf, &wcm, ipv4Addr)
			if err == nil && n > 0 {
				intf.SetFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMessageSent)
			}
		}
	}
	if c.ipv6conn != nil {
		// See https://pkg.go.dev/golang.org/x/net/ipv6#pkg-note-BUG
		// As of Golang 1.18.4
		// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
		var wcm ipv6.ControlMessage
		for _, intf := range c.interfaces {
			if !intf.HasFlags(NetInterfaceScopeIPv6, requiredFlags...) {
				continue
			}
			switch runtime.GOOS {
			case "darwin", "ios", "linux":
				wcm.IfIndex = intf.Index
			default:
				if err := c.ipv6conn.SetMulticastInterface(&intf.Interface); err != nil {
					log.Printf("[WARN] mdns: Failed to set multicast interface: %v", err)
				}
			}
			setDeadline(c.writeTimeout, c.ipv6conn)
			n, err := c.ipv6conn.WriteTo(buf, &wcm, ipv6Addr)
			if err == nil && n > 0 {
				intf.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMessageSent)
			}
		}
	}
	return nil
}
