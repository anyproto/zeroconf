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
// out of those selected by SelectIfaces: IPv4 keeps using all of them. What
// arrives over IPv6 on one of them is delivered as an entry of its own (see
// ServiceEntry.LinkIndex), apart from the once-per-TTL entry of every other
// answer, and again on a later answer there once two minutes have passed.
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
	// a delivery gives up only when the caller cancels, see mainloop
	callerDone := ctx.Done()
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
		c.mainloop(ctx, callerDone, params, msgCh)
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
	// with no family selected at all the client has no socket, as before
	if err := errors.Join(err4, err6); ipv4conn == nil && ipv6conn == nil && err != nil {
		return nil, err
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

// linkRedelivery is how long the delivery of an answer on a selected IPv6
// interface (see SelectIPv6Ifaces) holds back the next one from that link,
// so a subscriber hears again from a peer that keeps answering there. 120 s
// is the address TTL of RFC 6762 §10. A var so tests can shorten it.
var linkRedelivery = 120 * time.Second

// receivedMsg is a decoded packet with the index of the interface it arrived
// on (0 when the platform does not report it). v6 says it came from the IPv6
// socket.
type receivedMsg struct {
	msg     *dns.Msg
	ifIndex int
	v6      bool
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
func (c *client) mainloop(ctx context.Context, callerDone <-chan struct{}, params *lookupParams, msgCh <-chan receivedMsg) {
	// Iterate through channels from listeners goroutines
	var entries map[string]*ServiceEntry
	sentEntries := make(map[string]*ServiceEntry)
	// service type enumeration lists types, which belong to no link
	enumeration := params.ServiceRecord.ServiceTypeName() == params.ServiceRecord.ServiceName()
	// send delivers e unless the caller cancels first: the subscriber may
	// have stopped reading (a lookup takes its first result and cancels).
	// The end of probing (ctx) does not cut a packet short, as on develop.
	send := func(e *ServiceEntry) bool {
		select {
		case params.Entries <- e:
			return true
		case <-callerDone:
			params.done()
			c.shutdown()
			return false
		}
	}

	ticker := time.NewTicker(cleanupFreq)
	defer ticker.Stop()
	for {
		var (
			now       time.Time
			linkIndex int // see ServiceEntry.LinkIndex
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
				}
			}
			continue
		case received := <-msgCh:
			msg := received.msg
			now = time.Now()
			// a packet from the IPv6 socket on a selected interface is a
			// delivery stream of its own, so an answer over Wi-Fi does not
			// hide the one over the cable, nor the other way round
			if received.v6 && !enumeration {
				if _, ok := c.ipv6Ifaces[received.ifIndex]; ok {
					linkIndex = received.ifIndex
				}
			}
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
			for _, answer := range sections {
				switch rr := answer.(type) {
				case *dns.A:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv4 = append(entries[k].AddrIPv4, rr.A)
						}
					}
				case *dns.AAAA:
					for k, e := range entries {
						if e.HostName == rr.Hdr.Name {
							entries[k].AddrIPv6 = append(entries[k].AddrIPv6, rr.AAAA)
							if zoned, ok := zonedIPv6(rr.AAAA, received.ifIndex); ok {
								entries[k].AddrIPv6Zoned = append(entries[k].AddrIPv6Zoned, zoned)
							}
						}
					}
				}
			}
		}

		if len(entries) > 0 {
			for k, e := range entries {
				key := k
				if linkIndex != 0 {
					key = k + "|v6:" + strconv.Itoa(linkIndex)
				}
				if !e.Expiry.After(now) {
					delete(entries, k)
					delete(sentEntries, key)
					continue
				}
				// an expired delivery for a link stops holding its answers
				// back at once; for the instance key it waits for the
				// cleanup tick, as it always did
				if sent, ok := sentEntries[key]; ok && (linkIndex == 0 || sent.Expiry.After(now)) {
					continue
				}

				// If this is an DNS-SD query do not throw PTR away.
				// It is expected to have only PTR for enumeration
				if !enumeration {
					// Require at least one resolved IP address for ServiceEntry
					// TODO: wait some more time as chances are high both will arrive.
					if len(e.AddrIPv4) == 0 && len(e.AddrIPv6) == 0 {
						continue
					}
				}
				if linkIndex != 0 {
					e.LinkIndex = linkIndex
					// held back no longer than linkRedelivery, so the link
					// is delivered again while the peer keeps answering on it
					if limit := now.Add(linkRedelivery); e.Expiry.After(limit) {
						e.Expiry = limit
					}
				}
				// Submit entry to subscriber and cache it.
				// This is also a point to possibly stop probing actively for a
				// service entry.
				if !send(e) {
					return
				}
				sentEntries[key] = e
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
	_, v6 := l.(*ipv6.PacketConn)
	if v6 && c.ipv6Ifaces != nil {
		// the wildcard socket also takes unicast answers on other links
		accept = func(ifIndex int) bool {
			_, ok := c.ipv6Ifaces[ifIndex]
			return ok
		}
	}
	recvLoop(ctx, readFrom, v6, accept, msgCh)
}

// recvLoop reads packets via readFrom, unpacks them into dns.Msg structures
// and forwards them to msgCh until ctx is canceled or the connection is
// closed. Transient read errors are retried with a growing backoff (see
// nextRecvBackoff), mirroring the server recv loops: a persistently erroring
// socket must neither busy-spin a core nor silently kill reception. v6 marks
// the packets as read from the IPv6 socket; accept, when set, drops those
// from other interfaces.
func recvLoop(ctx context.Context, readFrom func([]byte) (n int, ifIndex int, err error), v6 bool, accept func(ifIndex int) bool, msgCh chan<- receivedMsg) {
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
		case msgCh <- receivedMsg{msg: msg, ifIndex: ifIndex, v6: v6}:
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
