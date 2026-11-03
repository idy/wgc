package wireguard

import (
	"bytes"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/idy/wgc/internal/header"
	cryptoutils "github.com/idy/wgc/internal/utils"
)

type handshakeResponseFixture struct {
	initiator  *Conn
	responder  *Conn
	peer       *peer
	session    *secureSession
	initiation []byte
	response   []byte
}

func newHandshakeResponseFixture(t *testing.T) handshakeResponseFixture {
	t.Helper()
	tr := newChannelTransport()
	initiator := channelConn(t, tr)
	responder := channelConn(t, newChannelTransport())
	t.Cleanup(func() { initiator.Close() })
	t.Cleanup(func() { responder.Close() })
	p, ok := initiator.peer(responder.PublicKey())
	if !ok {
		t.Fatal("initiator peer not admitted")
	}
	session := &secureSession{peer: p, isInitiator: true}
	if err := initiator.saveSession(session); err != nil {
		t.Fatal(err)
	}
	p.Lock()
	p.handshake = session
	p.Unlock()
	now := time.Now()
	writer := initiationWriter{
		buf:     make([]byte, header.HandshakeInitiationSize),
		session: session,
		start:   now,
		time:    now,
	}
	written := make(chan error, 1)
	go func() { written <- writer.Write() }()
	initiation := <-tr.outgoing
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	msg := responder.getInboundMessage()
	defer responder.putInboundMessage(msg)
	msg.data = msg.buf.BytesN(len(initiation.data))
	copy(msg.data, initiation.data)
	msg.time = now
	msg.typ = header.Initiation
	response, accepted := (*handshakeInitiation)(msg).Open()
	if !accepted {
		t.Fatal("valid initiation rejected")
	}
	return handshakeResponseFixture{
		initiator:  initiator,
		responder:  responder,
		peer:       p,
		session:    session,
		initiation: initiation.data,
		response:   bytes.Clone(response),
	}
}

func TestHandshakeResponseConcurrentDuplicates(t *testing.T) {
	fixture := newHandshakeResponseFixture(t)
	const workers = 32
	start := make(chan struct{})
	var wait sync.WaitGroup
	var accepted atomic.Int64
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			msg := &handshakeResponse{
				conn: fixture.initiator,
				time: time.Now(),
				data: bytes.Clone(fixture.response),
				typ:  header.Response,
			}
			if _, ok := msg.Open(); ok {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if count := accepted.Load(); count != 1 {
		t.Fatalf("accepted the same response %d times; want 1", count)
	}
	if state := fixture.session.Snapshot().state; state != confirmed {
		t.Fatalf("session state = %v; want confirmed", state)
	}
}

func TestHandshakeResponseRejectsUninitializedSession(t *testing.T) {
	fixture := newHandshakeResponseFixture(t)
	session := &secureSession{peer: fixture.peer, isInitiator: true}
	if err := fixture.initiator.saveSession(session); err != nil {
		t.Fatal(err)
	}
	message := header.HandshakeResponseMessage(bytes.Clone(fixture.response))
	message.SetReceiver(session.sender)
	prior, mac := header.MAC1(message)
	cryptoutils.Mac(mac, fixture.initiator.mac1VerifyKey, prior)
	msg := &handshakeResponse{conn: fixture.initiator, time: time.Now(), data: message, typ: header.Response}
	if _, accepted := msg.Open(); accepted {
		t.Fatal("response accepted before initiation state was initialized")
	}
}

func TestHandshakeInitiationRejectsDuplicateTimestamp(t *testing.T) {
	fixture := newHandshakeResponseFixture(t)
	msg := fixture.responder.getInboundMessage()
	defer fixture.responder.putInboundMessage(msg)
	msg.data = msg.buf.BytesN(len(fixture.initiation))
	copy(msg.data, fixture.initiation)
	msg.time = time.Now()
	msg.typ = header.Initiation
	if _, accepted := (*handshakeInitiation)(msg).Open(); accepted {
		t.Fatal("duplicate authenticated initiation was accepted")
	}
}

func TestEvictedPeerCancelsTimersAndCannotRestart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := channelConn(t, newChannelTransport())
		defer conn.Close()
		p, _ := installTransportSession(t, conn)
		p.Lock()
		p.handshakeInitiationDisabled = false
		p.next = &secureSession{peer: p}
		p.previous = &secureSession{peer: p}
		p.handshake = &secureSession{peer: p, isInitiator: true}
		p.handshakePending = true
		p.cookie[0] = 1
		p.startSetZeroTimer()
		p.startZeroCookieTimer()
		p.startPassiveKeepaliveTimer()
		p.startPassiveHandshakeTimer()
		timers := []*time.Timer{p.setZeroTimer, p.zeroCookieTimer, p.passiveKeepaliveTimer, p.passiveHandshakeTimer}
		p.Unlock()
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		for _, timer := range timers {
			if timer == nil {
				t.Fatal("peer timer did not start")
			}
			if timer.Stop() {
				t.Error("eviction left a live peer timer")
			}
		}
		if p.Unblock() || !p.IsBlocked() || !p.evicted.AtomicRead() {
			t.Fatal("evicted peer could be unblocked")
		}
		// A timer callback may already be waiting for peer.mu when Stop runs.
		p.SetZeroTimerFunc()
		p.ZeroCookieTimerFunc()
		p.PassiveKeepaliveTimerFunc()
		p.PassiveHandshakeTimerFunc()
		p.Lock()
		p.startSetZeroTimer()
		p.startZeroCookieTimer()
		p.startPassiveKeepaliveTimer()
		p.startPassiveHandshakeTimer()
		p.requestHandshakeLocked()
		if p.setZeroTimer != nil || p.zeroCookieTimer != nil || p.passiveKeepaliveTimer != nil || p.passiveHandshakeTimer != nil || p.handshakePending {
			t.Error("evicted peer restarted background work")
		}
		if p.next != nil || p.current != nil || p.previous != nil || p.handshake != nil || p.cookie != [header.CookieSize]byte{} {
			t.Error("eviction retained peer session state")
		}
		p.Unlock()
		p.InitiateHandshake()
		synctest.Wait()
	})
}

func TestPassiveHandshakeStartsAfterFifteenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		p, ok := conn.peer(testKey(t))
		if !ok {
			t.Fatal("peer not admitted")
		}
		p.Update(&PeerConfig{Addr: netip.MustParseAddrPort("127.0.0.1:51820")})
		p.Lock()
		p.dataWillSend = time.Now().Add(-10 * time.Minute)
		p.dataSent = time.Now()
		p.firstDataSentAfterRecv = p.dataSent
		p.startPassiveHandshakeTimer()
		p.Unlock()
		time.Sleep(15*time.Second - time.Nanosecond)
		select {
		case <-tr.outgoing:
			t.Fatal("passive handshake started before its deadline")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case packet := <-tr.outgoing:
			if typ := header.Type(packet.data); typ != header.Initiation {
				t.Fatalf("passive recovery sent %v; want initiation", typ)
			}
		default:
			t.Fatal("no passive handshake at 15 seconds with stale application activity")
		}
	})
}

func TestInitiationRetransmissionStopsImmediatelyOnClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		p, ok := conn.peer(testKey(t))
		if !ok {
			t.Fatal("peer not admitted")
		}
		p.Update(&PeerConfig{Addr: netip.MustParseAddrPort("127.0.0.1:51820")})
		stopped := make(chan struct{})
		go func() {
			p.InitiateHandshake()
			close(stopped)
		}()
		<-tr.outgoing
		synctest.Wait()
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-stopped:
		default:
			t.Fatal("initiation loop retained the closed connection until its retry timer")
		}
	})
}

func TestDiscardHandshakePreservesReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := channelConn(t, newChannelTransport())
		defer conn.Close()
		p, ok := conn.peer(testKey(t))
		if !ok {
			t.Fatal("peer not admitted")
		}
		old := &secureSession{peer: p, isInitiator: true}
		current := &secureSession{peer: p, isInitiator: true}
		if err := conn.saveSession(current); err != nil {
			t.Fatal(err)
		}
		p.Lock()
		p.handshake = current
		p.Unlock()
		p.discardHandshake(old)
		p.RLock()
		retained := p.handshake == current
		p.RUnlock()
		if !retained {
			t.Fatal("old initiation loop discarded its replacement handshake")
		}
		p.discardHandshake(current)
		synctest.Wait()
		if _, found := conn.session(current.sender); found {
			t.Fatal("discarded handshake remained in the session store")
		}
	})
}
