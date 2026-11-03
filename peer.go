package wireguard

import (
	"crypto/cipher"
	"net/netip"
	"sync"
	"time"

	"github.com/idy/wgc/internal/bufpool"
	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/utils"
)

type peer struct {
	// mac1GenerateKey is calculated by Hash(Label-Mac1 +
	// Peer-Static-Public-Key). It's used to calculate mac1 of handshake
	// initiation/response sending to peer.
	mac1GenerateKey []byte

	// cookieOpenCipher is used to open cookie reply messages. It's calculated
	// by Hash(Label-Cooki + Peer-Static-Public-Key).
	cookieOpenCipher cipher.AEAD

	conn      *Conn
	staticPub *Key
	psk       atomicKey
	// blocked marks this peer is blocked from recving and sending data.
	blocked atomicBool

	// evicted marks this peer is evicted from wg conn and should be discarded.
	evicted atomicBool

	mu sync.RWMutex

	// If true, stop updating addr by incoming messages.
	// +checklocks:mu
	addrRoamingDisabled bool

	// If true, no handshake will be initiated.
	// +checklocks:mu
	handshakeInitiationDisabled bool

	// +checklocks:mu
	addr netip.AddrPort

	// +checklocks:mu
	next *secureSession

	// +checklocks:mu
	current *secureSession

	// +checklocks:mu
	previous *secureSession

	// +checklocks:mu
	handshake *secureSession

	handshakeTimestampFilter timestampFilter

	// addrUpdated is the time of the latest addr update.
	// +checklocks:mu
	addrUpdated time.Time

	// dataSent is the time when the latest transport message data was sent.
	// +checklocks:mu
	dataSent time.Time

	// dataWillSend is the time when the latest data will be sent. This time is
	// used to calculate rekeyAttemptTime in handshake initiation send loop.
	// +checklocks:mu
	dataWillSend time.Time

	// firstDataSentAfterRecv is the time of the first sent transport data
	// message after the last receiving time of any type of message of transport
	// data, handshake initiation/response and keepalive. This value is used to
	// postpone the sending of a passive handshake. See
	// peer.PassiveHandshakeTimerFunc for more details.
	// +checklocks:mu
	firstDataSentAfterRecv time.Time

	// dataRecv is the time when the latest transport message data was received.
	// +checklocks:mu
	dataRecv time.Time

	// firstDataRecvAfterSent is the time of the first received transport data
	// message after the last sending time of any type of message of transport
	// data, handshake initiation/response and keepalive. This value is used to
	// postpone the sending of a passive keepalive. See
	// peer.PassiveKeepaliveTimerFunc for more details.
	// +checklocks:mu
	firstDataRecvAfterSent time.Time

	// keepaliveSent is the time when the latest keepalive message was sent.
	// +checklocks:mu
	keepaliveSent time.Time

	// keepaliveRecv is the time when the latest keepalive message was received.
	// +checklocks:mu
	keepaliveRecv time.Time

	// handshakeSent is the time when the latest handshake initiation/response
	// message was sent.
	// +checklocks:mu
	handshakeSent time.Time

	// handshakeRecv is the time when the latest handshake initiation/response
	// message was received.
	// +checklocks:mu
	handshakeRecv time.Time

	// cookieReplyRecv is the time when the latest cookie reply message was
	// received. This value is used to zero out peer.cookie. See
	// peer.ZeroCookieTimerFunc for details.
	// +checklocks:mu
	cookieReplyRecv time.Time

	// cookie is the lastest cookie received with a valie cookie reply message.
	// This value will be zeroed out by the timer after expiration.
	// +checklocks:mu
	cookie [header.CookieSize]byte

	// If setZeroTimer is true, it means that there is a running go routine
	// waiting to execute peer.SetZeroTimerFunc.
	// +checklocks:mu
	setZeroTimer bool

	// If zeroCookieTimer is true, it means that there is a running go routine
	// waiting to execute peer.ZeroCookieTimerFunc.
	// +checklocks:mu
	zeroCookieTimer bool

	// If passiveKeepaliveTimer is true, it means that there is a running go
	// routine waiting to execute peer.PassiveKeepaliveTimerFunc.
	// +checklocks:mu
	passiveKeepaliveTimer bool

	// If passiveHandshakeTimer is true, it means that there is a running go
	// routine waiting to execute peer.PassiveHandshakeTimerFunc.
	// +checklocks:mu
	passiveHandshakeTimer bool

	// This field is part of conn stats and is used to expose the status of the
	// peer to external users.
	stats *PeerStats
}

// +checklocksacquireread:p.mu
func (p *peer) RLock() {
	p.mu.RLock()
}

// +checklocksreleaseread:p.mu
func (p *peer) RUnlock() {
	p.mu.RUnlock()
}

// +checklocksacquire:p.mu
func (p *peer) Lock() {
	p.mu.Lock()
}

// +checklocksrelease:p.mu
func (p *peer) Unlock() {
	p.mu.Unlock()
}

// Block implements Peer.Block.
func (p *peer) Block() bool {
	p.Lock()
	defer p.Unlock()
	b := p.blocked.Read()
	p.blocked.SetTrue()
	return !b
}

// Unblock implements Peer.Unblock.
func (p *peer) Unblock() bool {
	p.Lock()
	defer p.Unlock()
	b := p.blocked.Read()
	p.blocked.SetFalse()
	return b
}

// IsBlocked implements Peer.IsBlocked.
func (p *peer) IsBlocked() bool {
	return p.blocked.AtomicRead()
}

// IsBlocked implements Peer.Update.
func (p *peer) Update(config *PeerConfig) {
	p.conn.stats.RLock()
	defer p.conn.stats.RUnlock()
	p.Lock()
	defer p.Unlock()
	p.addrRoamingDisabled = config.DisableAddrRoaming
	p.handshakeInitiationDisabled = config.DisableHandshakeInitiation
	if config.PSK != nil {
		p.psk.Set(*config.PSK)
	} else {
		p.psk.SetNil()
	}
	if config.Addr.IsValid() {
		if p.compareAndSetAddrUpdated(time.Now()) {
			p.addr = config.Addr
		}
	}
	addr := p.addr
	if !p.conn.stats.disabled {
		p.stats.RemoteAddr = addr
	}
}

// StaticPubKey implements Peer.StaticPubKey.
func (p *peer) StaticPubKey() Key {
	return *p.staticPub
}

// IsBlocked implements Peer.RemoteAddr.
func (p *peer) RemoteAddr() netip.AddrPort {
	p.RLock()
	defer p.RUnlock()
	return p.addr
}

func (p *peer) writeImmediately(b []byte) error {
	buf := bufpool.Get()
	defer bufpool.Put(buf)
	pw := peerWriter{peer: p, start: time.Now(), data: b}
	b, addr, err := pw.seal(buf.Bytes())
	if err != nil {
		return err
	}
	return pw.send(b, addr)
}

func (p *peer) Writer() *PeerWriter {
	return p.conn.PeerWriter(*p.staticPub)
}

// setMACs sets macs to dst and returns mac1 and mac2.
// +checklocksread:p.mu
func (p *peer) setMACs(dst []byte) (mac1, mac2 *[header.CookieSize]byte) {
	prior, m1 := header.MAC1(dst)
	utils.Mac(m1, p.mac1GenerateKey, prior)

	prior, m2 := header.MAC2(dst)
	utils.Mac(m2, p.cookie[:], prior)

	return m1, m2
}

// InitiateHandshake initiates a handshake and sends HandshakeInitiation
// requests repeatedly until the handshake succeeds or is discarded. If the
// peer's handshake is not nil, it means that the peer has initiated a handshake
// and the handshake is still in progress, so just continue to wait for the
// current handshake to complete.
//
// initiationSendLoop sends a handshake initiation request every rekeyTimeout +
// jitter seconds until rekeyAttemptTime seconds are looped. If the handshake
// session changes to another session when a request is sent, the loop will stop
// (a change of session means that the original handshake session has been
// converted to a current session or discarded, so this loop does not need to
// continue).
func (p *peer) InitiateHandshake() {
	p.RLock()
	if p.handshake != nil {
		p.RUnlock()
		p.logV(3).Print("A handshake is initiating")
		return
	}
	p.RUnlock()

	// We must ensure the lock order is conn.mu -> conn.stats.mu -> peer.mu,
	// otherwise we might deadlock.
	p.conn.mu.RLock()
	p.conn.stats.RLock()
	p.Lock()
	if p.handshake != nil {
		p.Unlock()
		p.conn.stats.RUnlock()
		p.conn.mu.RUnlock()
		p.logV(3).Print("A handshake is initiating")
		return
	}
	handshake := &secureSession{isInitiator: true, peer: p}
	if err := p.conn.saveSessionLocked(handshake); err != nil {
		p.Unlock()
		p.conn.stats.RUnlock()
		p.conn.mu.RUnlock()
		p.logV(1).Printf("InitiationHandshake: failed to save session: %v", err)
		return
	}

	p.handshake = handshake
	p.Unlock()
	p.conn.stats.RUnlock()
	p.conn.mu.RUnlock()
	p.logV(3).Print("Start a handshake initiation send loop")
	var buf [header.HandshakeInitiationSize]byte

	start := time.Now()

	for {
		if p.blocked.AtomicRead() {
			p.logV(3).Print("Retransmission stops: peer is blocked")
			break
		}
		now := time.Now()
		p.RLock()
		s, a, t := p.handshake, p.addr, p.dataWillSend
		p.RUnlock()
		if now.Sub(t) > rekeyAttemptTime {
			p.logV(3).Printf("Retransmission stops after %.2f seconds", rekeyAttemptTime.Seconds())
			break
		}
		if s != handshake {
			p.logV(3).Print("Retransmission stops: handshake is discarded or completed")
			return
		}
		if !a.IsValid() {
			p.logV(3).Printf("Retransmission: peer has no address")
		} else {
			w := initiationWriter{
				buf:     buf[:],
				addr:    a,
				session: s,
				start:   start,
				time:    now,
			}
			if err := w.Write(); err != nil {
				w.logV(3).Printf("Retransmission send error: %v", err)
			}
		}
		d := rekeyTimeout + randomJitter()
		p.logV(3).Printf("Retransmission sleep %.2f seconds for next round", d.Seconds())
		time.Sleep(d)
	}
	p.discardHandshake()
}

func (p *peer) discardHandshake() {
	p.Lock()
	defer p.Unlock()
	if p.handshake != nil {
		go p.conn.deleteSession(p.handshake)
		p.handshake = nil
	}
}

// +checklocks:p.mu
func (p *peer) startPassiveHandshakeTimer() {
	if !p.passiveHandshakeTimer {
		p.logV(3).Print("PassiveHandshake: timer started")
		p.passiveHandshakeTimer = true
		time.AfterFunc(rekeyAfterTime+keepaliveTimeout, p.PassiveHandshakeTimerFunc)
	} else {
		p.logV(3).Print("PassiveHandshake: timer existed")
	}
}

// PassiveHandshakeTimerFunc initiates a new handshake when no reply is received
// after sending the transport data message. This function first checks whether
// a new handshake needs to be initiated when it is triggered, and if necessary,
// a new handshake is initiated; otherwise, the timer trigger time is postponed
// as needed.
func (p *peer) PassiveHandshakeTimerFunc() {
	p.logV(3).Print("PassiveHandshake triggered")
	if p.blocked.AtomicRead() {
		p.logV(3).Print("PassiveHandshake stops: peer is blocked")
		p.Lock()
		defer p.Unlock()
		p.passiveHandshakeTimer = false
		return
	}

	p.RLock()
	recv := maxTime([]time.Time{p.dataRecv, p.keepaliveRecv, p.handshakeRecv})
	sent := p.dataSent
	firstSent := p.firstDataSentAfterRecv
	p.RUnlock()

	// 6.5 Passive Keepalive
	//
	// we can determine if the secure session is broken or disconnected if a
	// transport data message has not been received for (Keepalive-Timeout +
	// Rekey-Timeout) seconds.
	//
	// When this function is triggered, if the receiving time is later than the
	// sending time, it means that the secure session is kept in an active state
	// and there is no need to initiate a new handshake.
	skip := recv.After(sent)
	if !skip {
		// If the duration of the current time from firstSent is less than
		// (Rekey-Timeout + Keepalive - Timeout), the timer should be postponed.
		//
		// Data Sent (which start this timer) --> Auth Recv --> Data Sent
		// (another)
		if d := rekeyTimeout + keepaliveTimeout - time.Since(firstSent); d > 0 {
			p.logV(3).Printf("PassiveHandshake postponed for %.2f seconds", d.Seconds())
			time.AfterFunc(d, p.PassiveHandshakeTimerFunc)
			return
		}
	}

	p.Lock()
	defer p.Unlock()
	p.passiveHandshakeTimer = false
	if skip {
		p.logV(3).Print("PassiveHandshake skip")
		return
	}
	p.logV(3).Print("PassiveHandshake try to initiate handshake")
	go p.InitiateHandshake()
}

// startPassiveKeepaliveTimer starts a timer to send a keepalive message after
// keepaliveTimeout. If a peer has received a validly-authenticated transport data
// message, but does not have any packets itself to send back for
// Keepalive-Timeout seconds, it sends a keepalive message. A keepalive message
// is simply a transport data message with a zero-length encapsulated encrypted
// inner-packet.
// +checklocks:p.mu
func (p *peer) startPassiveKeepaliveTimer() {
	if !p.passiveKeepaliveTimer {
		p.logV(3).Print("PassiveKeepalive: timer started")
		p.passiveKeepaliveTimer = true
		time.AfterFunc(keepaliveTimeout, p.PassiveKeepaliveTimerFunc)
	} else {
		p.logV(3).Print("PassiveKeepalive: timer existed")
	}
}

func (p *peer) PassiveKeepaliveTimerFunc() {
	p.logV(3).Print("PassiveKeepalive triggered")
	if p.blocked.AtomicRead() {
		p.logV(3).Print("PassiveKeepalive stops: peer is blocked")
		p.Lock()
		defer p.Unlock()
		p.passiveKeepaliveTimer = false
		return
	}
	p.RLock()
	sent := maxTime([]time.Time{p.dataSent, p.keepaliveSent, p.handshakeSent})
	recv := p.dataRecv
	firstRecv := p.firstDataRecvAfterSent
	p.RUnlock()

	skip := sent.After(recv)
	if !skip {
		if d := keepaliveTimeout - time.Since(firstRecv); d > 0 {
			p.logV(3).Printf("PassiveKeepalive postponed for %.2f seconds", d.Seconds())
			time.AfterFunc(d, p.PassiveKeepaliveTimerFunc)
			return
		}
	}

	p.Lock()
	p.passiveKeepaliveTimer = false
	p.Unlock()
	if skip {
		p.logV(3).Print("PassiveKeepalive skip")
		return
	}
	p.logV(3).Print("PassiveKeepalive try to send keepalive message")
	p.writeImmediately(nil)
}

// +checklocks:p.mu
func (p *peer) startZeroCookieTimer() {
	if !p.zeroCookieTimer {
		p.logV(3).Print("ZeroCookie: timer started")
		p.zeroCookieTimer = true
		time.AfterFunc(cookieSecretRotationDuration, p.ZeroCookieTimerFunc)
	} else {
		p.logV(3).Print("ZeroCookie: timer existed")
	}
}

func (p *peer) ZeroCookieTimerFunc() {
	p.logV(3).Print("ZeroCookie triggered")
	if p.blocked.AtomicRead() {
		p.logV(3).Print("ZeroCookie stops: peer is blocked")
		p.Lock()
		defer p.Unlock()
		p.zeroCookieTimer = false
		return
	}
	p.RLock()
	d := cookieSecretRotationDuration - time.Since(p.cookieReplyRecv)
	p.RUnlock()

	if d > 0 {
		p.logV(3).Printf("ZeroCookie postponed for %.2f seconds", d.Seconds())
		// When the function is triggered, a new cookie reply is received, so
		// the current cookie is still valid, and the timer can be postponed.
		time.AfterFunc(d, p.ZeroCookieTimerFunc)
		return
	}

	p.Lock()
	defer p.Unlock()
	p.zeroCookieTimer = false
	copy(p.cookie[:], zeroBytes)
	p.logV(3).Print("ZeroCookie: OK")
}

// +checklocks:p.mu
func (p *peer) startSetZeroTimer() {
	if !p.setZeroTimer {
		p.logV(3).Print("SetZero: timer started")
		p.setZeroTimer = true
		time.AfterFunc(3*rejectAfterTime, p.SetZeroTimerFunc)
	} else {
		p.logV(3).Print("SetZero: timer existed")
	}
}

func (p *peer) SetZeroTimerFunc() {
	p.logV(3).Print("SetZero triggered")
	if p.blocked.AtomicRead() {
		p.logV(3).Print("SetZero stops: peer is blocked")
		p.Lock()
		defer p.Unlock()
		p.setZeroTimer = false
		return
	}
	p.RLock()
	t := maxTime([]time.Time{p.handshakeSent, p.handshakeRecv})
	p.RUnlock()

	d := 3*rejectAfterTime - time.Since(t)
	if d > 0 {
		p.logV(3).Printf("SetZero postponed for %.2f seconds", d.Seconds())
		time.AfterFunc(d, p.SetZeroTimerFunc)
		return
	}
	p.conn.evictPeer(p)
	p.logV(3).Print("Peer is zeroed and evicted")
}

func (p *peer) SetZero() []*secureSession {
	p.Lock()
	defer p.Unlock()
	copy(p.cookie[:], zeroBytes)
	ss := make([]*secureSession, 0, 4)
	if p.next != nil {
		ss = append(ss, p.next)
		p.next = nil
	}
	if p.current != nil {
		ss = append(ss, p.current)
		p.current = nil
	}
	if p.previous != nil {
		ss = append(ss, p.previous)
		p.previous = nil
	}
	if p.handshake != nil {
		ss = append(ss, p.handshake)
		p.handshake = nil
	}
	return ss
}

// +checklocks:p.mu
func (p *peer) rotateHandshakeSessionToCurrent() {
	if p.previous != nil {
		// delete session requires RLock of conn, but current functoin is locked
		// by peer.Lock. To avoid a deadlock, we have to ensure the lock order
		// is conn.Lock -> conn.stats.Lock -> peer.Lock, so we need delete the
		// session in a a go routine.
		go p.conn.deleteSession(p.previous)
	}
	p.previous = p.current
	p.current = p.handshake
	p.handshake = nil
}

// +checklocks:p.mu
func (p *peer) rotateNextSessionToCurrent() {
	if p.previous != nil {
		go p.conn.deleteSession(p.previous)
	}
	p.previous = p.current
	p.current = p.next
	p.next = nil
}

// +checklocks:p.mu
func (p *peer) setNextSession(s *secureSession) {
	if p.previous != nil {
		go p.conn.deleteSession(p.previous)
		p.previous = nil
	}
	if p.next != nil {
		go p.conn.deleteSession(p.next)
	}
	p.next = s
}

// +checklocks:p.mu
func (p *peer) evictCurrentSession() {
	if p.current != nil {
		go p.conn.deleteSession(p.current)
		p.current = nil
	}
}

// +checklocks:p.mu
func (p *peer) compareAndSetDataSent(t time.Time) bool {
	return compareAndAssignTime(&p.dataSent, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetDataWillSend(t time.Time) bool {
	return compareAndAssignTime(&p.dataWillSend, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetDataRecv(t time.Time) bool {
	return compareAndAssignTime(&p.dataRecv, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetFirstDataRecvAfterSent(t time.Time) bool {
	return compareAndAssignTime(&p.firstDataRecvAfterSent, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetFirstDataSentAfterRecv(t time.Time) bool {
	return compareAndAssignTime(&p.firstDataSentAfterRecv, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetKeepaliveSent(t time.Time) bool {
	return compareAndAssignTime(&p.keepaliveSent, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetKeepaliveRecv(t time.Time) bool {
	return compareAndAssignTime(&p.keepaliveRecv, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetHandshakeSent(t time.Time) bool {
	return compareAndAssignTime(&p.handshakeSent, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetHandshakeRecv(t time.Time) bool {
	return compareAndAssignTime(&p.handshakeRecv, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetCookieReplyRecv(t time.Time) bool {
	return compareAndAssignTime(&p.cookieReplyRecv, t)
}

// +checklocks:p.mu
func (p *peer) compareAndSetAddrUpdated(t time.Time) bool {
	return compareAndAssignTime(&p.addrUpdated, t)
}
