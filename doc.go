// Package wireguard provides authenticated, encrypted, message-oriented
// connections using WireGuard handshakes and transport messages. Connections
// address peers by their static public keys and run over a pluggable Transport.
//
// The module path is github.com/idy/wgc; the package name remains wireguard.
// It does not configure TUN devices, IP routes, or a userspace TCP/IP stack.
// Applications decide how to authorize peers and interpret message payloads.
package wireguard
