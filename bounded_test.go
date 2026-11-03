package wireguard

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

type testUDP struct{ *net.UDPConn }

func (t testUDP) ReadFrom(b []byte) (int, netip.AddrPort, error)  { return t.ReadFromUDPAddrPort(b) }
func (t testUDP) WriteTo(b []byte, a netip.AddrPort) (int, error) { return t.WriteToUDPAddrPort(b, a) }
func boundedConn(t *testing.T) *Conn {
	t.Helper()
	udp, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	c, e := NewConn(testUDP{udp}, Config{MaxPeers: 2, DisableStats: true, SharedWriteQueue: true, PeerConfigLookup: func(Key) (*PeerConfig, error) { return &PeerConfig{DisableHandshakeInitiation: true}, nil }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func testKey(t *testing.T) Key {
	t.Helper()
	var sk, pk Key
	if e := GenerateKeys(&sk, &pk); e != nil {
		t.Fatal(e)
	}
	return pk
}
func TestBoundedPeersAndDisabledStats(t *testing.T) {
	c := boundedConn(t)
	a, b, d := testKey(t), testKey(t), testKey(t)
	p, ok := c.Peer(a)
	if !ok {
		t.Fatal("first peer")
	}
	if _, ok = c.Peer(b); !ok {
		t.Fatal("second peer")
	}
	if _, ok = c.Peer(d); ok {
		t.Fatal("peer limit bypassed")
	}
	if c.peerCount.Load() != 2 {
		t.Fatal("bad reservation count")
	}
	c.evictPeer(p.(*peer))
	if _, ok = c.Peer(d); !ok {
		t.Fatal("evicted slot not reusable")
	}
	count := 0
	c.stats.peers.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatal("peer history retained")
	}
	stats, _ := c.CaptureStats()
	if stats.PeersJoin != 0 || len(stats.Peers) != 0 {
		t.Fatal("disabled statistics collected")
	}
	c.Close()
	if c.peerCount.Load() != 0 {
		t.Fatal("peer state survived shutdown")
	}
}
func TestSharedQueueConcurrentShutdown(t *testing.T) {
	c := boundedConn(t)
	pk := testKey(t)
	var wg sync.WaitGroup
	started := make(chan struct{}, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.WriteTo([]byte("before close"), pk)
			started <- struct{}{}
			for j := 0; j < 100; j++ {
				c.WriteTo([]byte("test"), pk)
			}
		}()
	}
	// Exercise shutdown after every sender has entered the write path,
	// rather than sometimes closing before any worker is scheduled.
	for i := 0; i < 8; i++ {
		<-started
	}
	c.Close()
	wg.Wait()
	count := 0
	c.peerWriters.Range(func(_, _ any) bool { count++; return true })
	if count != 0 {
		t.Fatal("shared writes retained per-peer writers")
	}
}
