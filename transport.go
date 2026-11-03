package wireguard

import "net/netip"

// Transport exchanges WireGuard messages with remote endpoints. Applications
// supply a Transport to NewConn to configure how each connection sends and
// receives messages. The transport package provides a standard UDP adapter;
// application-specific transports and wrappers can implement this interface.
//
// Implementations must support a reader and concurrent writers. They must not
// retain the supplied buffers after a method returns.
type Transport interface {
	// ReadFrom reads one message into b and returns its sender's endpoint.
	// IPv4 endpoints should use an unmapped IPv4 address.
	ReadFrom(b []byte) (int, netip.AddrPort, error)
	// WriteTo sends one message to addr.
	WriteTo(b []byte, addr netip.AddrPort) (int, error)
	// Close closes the transport and unblocks pending I/O.
	Close() error
}
