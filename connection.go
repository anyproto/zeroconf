package zeroconf

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// Multicast groups used by mDNS
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: 5353,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP: net.ParseIP("ff02::"),
		// IP:   net.ParseIP("fd00::12d3:26e7:48db:e7d"),
		Port: 5353,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: 5353,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: 5353,
	}
)

func createCustomUDPConn(localAddress *net.UDPAddr, interfaceIndex int) (*net.UDPConn, error) {
	// Create socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Set SO_REUSEPORT
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil {
		syscall.Close(sock)
		return nil, fmt.Errorf("failed to set SO_REUSEPORT: %w", err)
	}

	// Set IP_BOUND_IF
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_BOUND_IF, interfaceIndex); err != nil {
		syscall.Close(sock)
		return nil, fmt.Errorf("failed to set IP_BOUND_IF: %w", err)
	}

	// Set SO_BROADCAST
	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
		syscall.Close(sock)
		return nil, fmt.Errorf("failed to set SO_BROADCAST: %w", err)
	}

	// Bind
	sockaddr := &syscall.SockaddrInet4{Port: localAddress.Port}
	copy(sockaddr.Addr[:], localAddress.IP.To4())
	if err := syscall.Bind(sock, sockaddr); err != nil {
		syscall.Close(sock)
		return nil, fmt.Errorf("failed to bind: %w", err)
	}

	// Convert the socket FD to a net.UDPConn
	file := os.NewFile(uintptr(sock), "mdnsUDP")
	udpConn, err := net.FilePacketConn(file)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to convert FD to UDPConn: %w", err)
	}

	return udpConn.(*net.UDPConn), nil
}

func joinUdp6Multicast(interfaces []*NetInterface) (*ipv6.PacketConn, error) {
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces to join multicast on")
	}

	udpConn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv6.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv6.FlagInterface, true)

	// log.Println("Using multicast interfaces: ", interfaces)
	var anySucceeded bool
	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface.Interface, &net.UDPAddr{IP: mdnsGroupIPv6}); err == nil {
			traceln("Joined IPv6 multicast on interface: ", iface.Name)

			iface.SetFlag(NetInterfaceScopeIPv6, NetInterfaceStateFlagMulticastJoined)
			anySucceeded = true
		}
	}
	if !anySucceeded {
		pkConn.Close()
		return nil, fmt.Errorf("udp6: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastHopLimit(255)

	return pkConn, nil
}

func joinUdp4Multicast(interfaces []*NetInterface) (*ipv4.PacketConn, error) {
	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no interfaces to join multicast on")
	}

	//udpConn, err := createCustomUDPConn(mdnsWildcardAddrIPv4, 12)
	udpConn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		// log.Printf("[ERR] bonjour: Failed to bind to udp4 mutlicast: %v", err)
		return nil, err
	}

	// Join multicast groups to receive announcements
	pkConn := ipv4.NewPacketConn(udpConn)
	pkConn.SetControlMessage(ipv4.FlagInterface, true)

	// log.Println("Using multicast interfaces: ", interfaces)
	var anySucceed bool

	for _, iface := range interfaces {
		if err := pkConn.JoinGroup(&iface.Interface, &net.UDPAddr{IP: mdnsGroupIPv4}); err == nil {
			traceln("Joined IPv4 multicast on interface: ", iface.Name)
			anySucceed = true
			iface.SetFlag(NetInterfaceScopeIPv4, NetInterfaceStateFlagMulticastJoined)
		}
	}
	if !anySucceed {
		pkConn.Close()
		return nil, fmt.Errorf("udp4: failed to join any of these interfaces: %v", interfaces)
	}

	_ = pkConn.SetMulticastTTL(255)

	return pkConn, nil
}

func listMulticastInterfaces() []net.Interface {
	var interfaces []net.Interface
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}
		if (ifi.Flags & net.FlagMulticast) > 0 {
			interfaces = append(interfaces, ifi)
		}
	}

	return interfaces
}
