package transport

import (
	"net"
	"net/netip"
)

// UDPConn adapts a listening UDP socket to a WireGuard message transport.
type UDPConn struct {
	uc *net.UDPConn
}

// FromUDPConn wraps a listening socket. Closing the adapter closes the socket.
func FromUDPConn(uc *net.UDPConn) *UDPConn {
	return &UDPConn{uc: uc}
}

func (uc *UDPConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	for {
		n, ap, err := uc.uc.ReadFromUDPAddrPort(b)
		if isDatagramTooLarge(err) {
			// Windows consumes the datagram but reports a truncated payload.
			continue
		}
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
	}
}

func (uc *UDPConn) WriteTo(b []byte, addr netip.AddrPort) (int, error) {
	return uc.uc.WriteToUDPAddrPort(b, addr)
}

func (uc *UDPConn) Close() error {
	return uc.uc.Close()
}
