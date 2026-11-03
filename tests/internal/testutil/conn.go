package testutil

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	wireguard "github.com/idy/wgc"
	"github.com/idy/wgc/transport"
)

func Keys(tb testing.TB) (private, public wireguard.Key) {
	tb.Helper()
	if err := wireguard.GenerateKeys(&private, &public); err != nil {
		tb.Fatal(err)
	}
	return private, public
}

func NewConn(tb testing.TB, config wireguard.Config) *wireguard.Conn {
	tb.Helper()
	return newConn(tb, ListenUDP(tb), config)
}

func newConn(tb testing.TB, socket *net.UDPConn, config wireguard.Config) *wireguard.Conn {
	tb.Helper()
	conn, err := wireguard.NewConn(transport.FromUDPConn(socket), config)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	return conn
}

type Pair struct {
	Left  *wireguard.Conn
	Right *wireguard.Conn
}

// NewPair completes a real UDP handshake before returning. Either connection
// can then send application payloads without depending on handshake retries.
func NewPair(tb testing.TB, psk *wireguard.Key) Pair {
	tb.Helper()
	leftKey, leftPublic := Keys(tb)
	rightKey, rightPublic := Keys(tb)
	leftSocket, rightSocket := ListenUDP(tb), ListenUDP(tb)
	config := func(private *wireguard.Key, remote wireguard.Key, addr netip.AddrPort) wireguard.Config {
		return wireguard.Config{
			StaticPrivateKey: private,
			MaxPeers:         1,
			ReadQueueSize:    16,
			WriteQueueSize:   16,
			PeerConfigLookup: func(key wireguard.Key) (*wireguard.PeerConfig, error) {
				if key != remote {
					return nil, nil
				}
				return &wireguard.PeerConfig{PSK: psk, Addr: addr}, nil
			},
		}
	}
	pair := Pair{
		Left:  newConn(tb, leftSocket, config(&leftKey, rightPublic, rightSocket.LocalAddr().(*net.UDPAddr).AddrPort())),
		Right: newConn(tb, rightSocket, config(&rightKey, leftPublic, leftSocket.LocalAddr().(*net.UDPAddr).AddrPort())),
	}
	ready := make(chan error, 1)
	go func() {
		buffer := make([]byte, wireguard.MaximumDataSize)
		n, peer, err := pair.Right.ReadFrom(buffer)
		if err == nil && (n != 0 || peer.StaticPubKey() != leftPublic) {
			err = fmt.Errorf("unexpected handshake confirmation from %v", peer)
		}
		ready <- err
	}()
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
	deadline := time.NewTimer(IOTimeout)
	defer deadline.Stop()
	for {
		if _, _, err := pair.Left.WriteTo(nil, rightPublic); err != nil {
			tb.Fatal(err)
		}
		select {
		case err := <-ready:
			if err != nil {
				tb.Fatalf("handshake confirmation: %v", err)
			}
			return pair
		case <-retry.C:
		case <-deadline.C:
			tb.Fatal("UDP handshake timed out")
		}
	}
}

func ReadPayload(tb testing.TB, conn *wireguard.Conn) ([]byte, wireguard.Peer) {
	tb.Helper()
	type result struct {
		data []byte
		peer wireguard.Peer
		err  error
	}
	received := make(chan result, 1)
	go func() {
		buffer := make([]byte, wireguard.MaximumDataSize)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil || n > 0 {
				received <- result{buffer[:n], peer, err}
				return
			}
		}
	}()
	deadline := time.NewTimer(IOTimeout)
	defer deadline.Stop()
	select {
	case value := <-received:
		if value.err != nil {
			tb.Fatal(value.err)
		}
		return value.data, value.peer
	case <-deadline.C:
		tb.Fatal("authenticated payload timed out")
		return nil, nil
	}
}
