package wireguard

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type channelDatagram struct {
	data []byte
	addr netip.AddrPort
	err  error
}

type channelTransport struct {
	incoming chan channelDatagram
	outgoing chan channelDatagram
	done     chan struct{}
	once     sync.Once
}

func newChannelTransport() *channelTransport {
	return &channelTransport{
		incoming: make(chan channelDatagram, 8),
		outgoing: make(chan channelDatagram),
		done:     make(chan struct{}),
	}
}

func (tr *channelTransport) ReadFrom(buffer []byte) (int, netip.AddrPort, error) {
	select {
	case <-tr.done:
		return 0, netip.AddrPort{}, net.ErrClosed
	case packet := <-tr.incoming:
		if packet.err != nil {
			return 0, packet.addr, packet.err
		}
		return copy(buffer, packet.data), packet.addr, nil
	}
}

func (tr *channelTransport) WriteTo(data []byte, addr netip.AddrPort) (int, error) {
	packet := channelDatagram{data: append([]byte(nil), data...), addr: addr}
	select {
	case <-tr.done:
		return 0, net.ErrClosed
	case tr.outgoing <- packet:
		return len(data), nil
	}
}

func (tr *channelTransport) Close() error {
	tr.once.Do(func() { close(tr.done) })
	return nil
}

func channelConn(t *testing.T, tr *channelTransport) *Conn {
	t.Helper()
	conn, err := NewConn(tr, Config{
		ReadQueueSize:  1,
		WriteQueueSize: 1,
		DisableStats:   true,
		PeerConfigLookup: func(Key) (*PeerConfig, error) {
			return &PeerConfig{DisableHandshakeInitiation: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func installTransportSession(t *testing.T, conn *Conn) (*peer, func(uint64) *transportData) {
	t.Helper()
	fixture, packet := transportReceiver(t)
	session, _ := fixture.session(7)
	p, ok := conn.peer(testKey(t))
	if !ok {
		t.Fatal("peer not admitted")
	}
	session.peer = p
	session.sender = 7
	session.sendCipher = session.recvCipher
	p.current = session
	conn.sessionStore.Store(uint32(7), session)
	return p, packet
}

func TestCloseWithFullReadQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		_, packet := installTransportSession(t, conn)
		for counter := range uint64(2) {
			tr.incoming <- channelDatagram{data: packet(counter).data, addr: netip.MustParseAddrPort("127.0.0.1:51820")}
		}
		synctest.Wait()
		if len(conn.readQueue) != 1 {
			t.Fatal("receive queue was not filled")
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		// The bubble must finish without an application draining queued packets.
	})
}

func TestPeerWriterCloseUnblocksPendingWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		p, _ := installTransportSession(t, conn)
		writer := p.Writer()
		const writes = 6
		results := make(chan error, writes)
		for range writes {
			go func() {
				_, err := writer.Write([]byte("pending"))
				results <- err
			}()
		}
		synctest.Wait()
		closed := make(chan struct{})
		go func() {
			writer.Close()
			close(closed)
		}()
		synctest.Wait()
		select {
		case <-closed:
		default:
			t.Fatal("writer Close is blocked behind a pending write")
		}
		for range writes {
			<-results
		}
	})
}

func TestTerminalReadErrorClosesConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		failure := errors.New("transport receive failed")
		tr.incoming <- channelDatagram{err: failure}
		_, _, err := conn.ReadFrom(make([]byte, 32))
		if !errors.Is(err, failure) {
			t.Errorf("read error = %v; want transport failure", err)
		}
		conn.mu.RLock()
		closed := conn.closed
		conn.mu.RUnlock()
		if !closed {
			t.Error("terminal read error left connection open")
		}
		if _, _, err := conn.WriteTo([]byte("after failure"), testKey(t)); err == nil {
			t.Error("write admitted after terminal read failure")
		}
	})
}

func TestCaptureStatsReturnsIntervalStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		start := time.Now()
		conn := channelConn(t, tr)
		defer conn.Close()
		time.Sleep(time.Second)
		_, first := conn.CaptureStats()
		if !first.Equal(start) {
			t.Fatalf("first interval start = %v; want %v", first, start)
		}
		start = time.Now()
		time.Sleep(time.Second)
		_, second := conn.CaptureStats()
		if !second.Equal(start) {
			t.Fatalf("second interval start = %v; want %v", second, start)
		}
	})
}

func TestPeerWriterUsesConfiguredQueueSize(t *testing.T) {
	tr := newChannelTransport()
	conn := channelConn(t, tr)
	defer conn.Close()
	writer := conn.PeerWriter(testKey(t))
	if capacity := cap(writer.sendQueue.deliveryQueue); capacity != 1 {
		t.Fatalf("writer delivery capacity = %d; want configured size 1", capacity)
	}
}

func TestImplicitWritersRetireWithoutClosingExplicitWriter(t *testing.T) {
	conn := channelConn(t, newChannelTransport())
	defer conn.Close()
	key := testKey(t)
	explicit := conn.PeerWriter(key)
	for range 8 {
		_, current, err := conn.WriteTo([]byte("queued"), key)
		if err != nil {
			t.Fatal(err)
		}
		if !conn.evictPeer(current.(*peer)) {
			t.Fatal("peer was not evicted")
		}
		retained := 0
		conn.autoWriters.Range(func(_, _ any) bool { retained++; return true })
		if retained != 0 {
			t.Fatal("eviction retained an implicit writer")
		}
		if _, err := explicit.Write([]byte("reused")); err != nil {
			t.Fatalf("explicit writer failed after peer eviction: %v", err)
		}
	}
}

func TestConcurrentImplicitWriterShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := channelConn(t, newChannelTransport())
		defer conn.Close()
		key := testKey(t)
		const workers = 8
		started := make(chan struct{}, workers)
		var wait sync.WaitGroup
		for range workers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				conn.WriteTo([]byte("before shutdown"), key)
				started <- struct{}{}
				for range 32 {
					conn.WriteTo([]byte("concurrent"), key)
				}
			}()
		}
		for range workers {
			<-started
		}
		conn.Close()
		wait.Wait()
		retained := 0
		conn.autoWriters.Range(func(_, _ any) bool { retained++; return true })
		if retained != 0 {
			t.Fatal("shutdown retained implicit writers")
		}
	})
}

func TestConcurrentPeerStatisticsPublication(t *testing.T) {
	tr := newChannelTransport()
	conn, err := NewConn(tr, Config{PeerConfigLookup: func(Key) (*PeerConfig, error) {
		return &PeerConfig{DisableHandshakeInitiation: true}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	finished := make(chan struct{})
	var capture sync.WaitGroup
	capture.Add(1)
	go func() {
		defer capture.Done()
		for {
			select {
			case <-finished:
				return
			default:
				conn.CaptureStats()
			}
		}
	}()
	const peers = 32
	for range peers {
		if _, ok := conn.Peer(testKey(t)); !ok {
			t.Error("peer not admitted")
		}
	}
	close(finished)
	capture.Wait()
	stats, _ := conn.CaptureStats()
	if len(stats.Peers) != peers {
		t.Fatalf("captured %d live peers; want %d", len(stats.Peers), peers)
	}
	for _, peer := range stats.Peers {
		if peer.peerPtr != nil {
			t.Fatal("captured statistics retained a live peer")
		}
	}
}

func TestRejectedWriteDoesNotRetainWriters(t *testing.T) {
	tr := newChannelTransport()
	conn, err := NewConn(tr, Config{DisableStats: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for range 8 {
		if _, _, err := conn.WriteTo([]byte("denied"), testKey(t)); !errors.Is(err, ErrPeerNotFound) {
			t.Fatalf("denied write error = %v", err)
		}
	}
	retained := 0
	conn.peerWriters.Range(func(_, _ any) bool { retained++; return true })
	conn.autoWriters.Range(func(_, _ any) bool { retained++; return true })
	if retained != 0 {
		t.Fatalf("denied writes retained %d writers", retained)
	}
}
