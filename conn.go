package wireguard

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/idy/wgc/internal/bufpool"
	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/logger"
	netutils "github.com/idy/wgc/internal/netutil"
	"github.com/idy/wgc/internal/utils"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaximumMessageSize = bufpool.DefaultSize
	MaximumDataSize    = MaximumMessageSize - header.EmptyTransportDataSize
)

var (
	ErrPeerNotFound  = errors.New("netutils/wireguard: peer not found")
	ErrPeerBlocked   = errors.New("netutils/wireguard: peer blocked")
	ErrPeerNoSession = errors.New("netutils/wireguard: peer has no session")

	errInvalidPacket = fmt.Errorf("netutils/wireguard: %w", netutils.ErrInvalidPacket)
	errConnClosed    = fmt.Errorf("netutils/wireguard: %w", net.ErrClosed)
)

// A PeerWriter is writer that write data to Peer. It caches and updates the
// underlying peer for writing data.
type PeerWriter struct {
	mu sync.RWMutex
	pk Key

	sendQueue *sendQueue

	// +checklocks:mu
	conn *Conn

	// +checklocks:mu
	p *peer
}

// PeerPublicKey returns the public key of the peer writer.
func (w *PeerWriter) PeerPublicKey() Key {
	return w.pk
}

func (w *PeerWriter) peer() (*peer, bool) {
	w.mu.RLock()
	peer := w.p
	if peer != nil && peer.evicted.AtomicRead() {
		peer = nil
	}
	w.mu.RUnlock()
	if peer != nil {
		return peer, true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	peer, ok := w.conn.peer(w.pk)
	if !ok {
		return nil, false
	}
	w.p = peer
	return peer, true
}

func (w *PeerWriter) Peer() (Peer, bool) {
	return w.peer()
}

func (w *PeerWriter) Close() error {
	w.sendQueue.Close()
	return nil
}

// Write writes data to a active peer. If no peer is active, returns
// ErrPeerNotFound error.
func (w *PeerWriter) Write(b []byte) (int, error) {
	n, _, err := w.WriteToPeer(b)
	return n, err
}

// WriteChunks merges the chunks and writes the merged data to a active peer.
func (w *PeerWriter) WriteChunks(chunks [][]byte) (int, error) {
	n, _, err := w.WriteChunksToPeer(chunks)
	return n, err
}

// WriteToPeer writes data to a active peer and returns the peer with the write
// result.
func (w *PeerWriter) WriteToPeer(b []byte) (int, Peer, error) {
	return w.WriteChunksToPeer([][]byte{b})
}

func (w *PeerWriter) WriteChunksToPeer(chunks [][]byte) (int, Peer, error) {
	p, ok := w.peer()
	if !ok {
		return 0, nil, ErrPeerNotFound
	}
	n, err := w.sendQueue.enqueueChunks(chunks, p)
	if err != nil {
		return 0, nil, &ioError{
			Op:   "write",
			Err:  err,
			Peer: p.staticPub,
		}
	}
	return n, p, nil
}

type (
	// The PeerConfig structure uses to config a Peer.
	PeerConfig struct {
		// The preshared key of the peer.
		PSK *Key

		// The preset public endpoint of the peer.
		Addr netip.AddrPort

		// If true, the peer will not update it's public endpoint when receiving
		// authenticated messages.
		DisableAddrRoaming bool

		// If true, no handshake will be initiated to the peer.
		DisableHandshakeInitiation bool
	}

	// Peer describes the operations that users can perform on a WireGuard Peer.
	Peer interface {
		// Block blocks the peer from communicating. All data written and
		// received during the blocking period will not be saved.
		Block() bool

		// IsBlocked returns whether this peer is blocked.
		IsBlocked() bool

		// Unblock resumes peer communication.
		Unblock() bool

		// Update configs peer.
		Update(*PeerConfig)

		// StaticPubKey returns a clone version of the peer's static public key.
		StaticPubKey() Key

		// RemoteAddr returns the peer's remote addr.
		RemoteAddr() netip.AddrPort

		// Writer returns a PeerWriter for more efficient writing.
		Writer() *PeerWriter
	}

	// The Config structure uses to config a wireguard connection.
	Config struct {
		// If nil, a random key will be generated. Users can read it with
		// WGConn.PrivateKey method.
		StaticPrivateKey *Key

		// If nil all peer will be block by default. Users can use Peer.Update
		// of Peer.Unblock to resume communication with them.
		PeerConfigLookup func(Key) (*PeerConfig, error)

		// If not specified, the default value is 1024.
		ReadQueueSize int

		// If not specified, the default value is 1024.
		WriteQueueSize int

		// MaxPeers bounds live handshake identities. Zero preserves the legacy
		// unlimited behavior; rejected new peers may retry after eviction.
		MaxPeers int
		// DisableStats disables peer history and traffic counters.
		DisableStats bool
		// SharedWriteQueue avoids a permanent writer/queue per destination when
		// using Conn.WriteTo. Explicit PeerWriter users keep their own queues.
		SharedWriteQueue bool
	}
)

func (cfg *Config) readQueueSize() int {
	if cfg.ReadQueueSize <= 0 {
		return 1024
	}
	return cfg.ReadQueueSize
}

func (cfg *Config) writeQueueSize() int {
	if cfg.WriteQueueSize <= 0 {
		return 1024
	}
	return cfg.WriteQueueSize
}

// Conn is a connection based on the WireGuard protocol. It is used to transmit
// message data to and from the authenticated Peer through UDP. An additional
// mechanism is needed to ensure the order and continuity of the data. Peer
// authentication is based on WireGuard's handshake process, which is
// automatically completed by goroutines running in the background.
type Conn struct {
	transport  Transport
	readQueue  <-chan Packet
	writeQueue *writeQueue

	// precomputed mac value used to verify mac1 of receiving handshake
	// initiation/response.
	mac1VerifyKey []byte
	cookieSecret  [blake2s.Size]byte
	csgTime       time.Time

	// cookieSealCipher is used to seal cookie reply messages.
	cookieSealCipher cipher.AEAD

	staticPriv *Key
	staticPub  *Key

	// This function is only called when the peer's public key is first seen,
	// and then the cached data will be used. If the call returns nil, a blocked
	// peer is generated by default; if an error is returned, it will not be
	// cached. If you need to update the peer, you can use the Peer.Update
	// method.
	peerConfigLookup func(Key) (*PeerConfig, error)

	// mu is used to close the wireguard. RLock when adding a peer or session,
	// and Lock when closing wireguard. This ensures that there will be no new
	// peers or sessions during and after closing.
	mu sync.RWMutex
	// +checklocks:mu
	closed bool

	sessionStore sync.Map
	peerStore    sync.Map
	peerWriters  sync.Map
	peerCount    atomic.Int64
	maxPeers     int64
	sharedWrite  *sendQueue

	// these variables are used to record the internal state of conn at runtime.
	stats          statsCounter
	statsResetTime time.Time

	// UnderLoad indicates whether the host is busy. Users can set UnderLoad to
	// true or false. If set true, all handshakes require a valid mac2.
	UnderLoad atomicBool
}

func NewConn(transport Transport, config Config) (*Conn, error) {
	var sk, pk Key
	if config.StaticPrivateKey != nil {
		sk = *config.StaticPrivateKey
	}
	if err := utils.DHGenerate(&sk, &pk); err != nil {
		return nil, err
	}

	var mac1Key [blake2s.Size]byte
	utils.Hash(&mac1Key, []byte(mac1Label), pk[:])

	var cookieReplyKey [blake2s.Size]byte
	utils.Hash(&cookieReplyKey, []byte(cookieLabel), pk[:])

	cipher, err := chacha20poly1305.NewX(cookieReplyKey[:])
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		transport:        transport,
		mac1VerifyKey:    mac1Key[:],
		cookieSealCipher: cipher,

		staticPriv: &sk,
		staticPub:  &pk,

		peerConfigLookup: config.PeerConfigLookup,
		maxPeers:         int64(config.MaxPeers),
	}
	conn.stats.disabled = config.DisableStats
	conn.stats.TxStats.disabled = config.DisableStats
	conn.readQueue = streamRead(conn, config.readQueueSize())
	conn.writeQueue = newWriteQueue(config.writeQueueSize())
	if config.SharedWriteQueue {
		conn.sharedWrite = conn.writeQueue.newSendQueue(config.writeQueueSize())
	}
	return conn, nil
}

// Stats is a struct that contains the internal status of WireGuard connections.
type Stats struct {
	ConnStats
	TxStats
	Peers map[Key]PeerStats
}

// CaptureStats captures the status of the current connection, returns the
// status and the start time of the status counter. After calling this function,
// the status counter will be reset and the current time will be set as the
// start time of a new round of counter. The new connection will set the counter
// start time when ReadFrom is called for the first time.
func (conn *Conn) CaptureStats() (Stats, time.Time) {
	conn.stats.Lock()
	defer conn.stats.Unlock()
	s := Stats{
		ConnStats: conn.stats.ConnStats,
		TxStats:   conn.stats.TxStats,
		Peers:     make(map[Key]PeerStats),
	}
	conn.stats.peers.Range(func(k, v interface{}) bool {
		ps := v.(*PeerStats)
		s.Peers[k.(Key)] = *ps
		if atomic.LoadPointer(&ps.peerPtr) == nil {
			conn.stats.peers.Delete(k)
		} else {
			ps.TxStats = TxStats{}
		}
		return true
	})
	conn.stats.ConnStats = ConnStats{}
	conn.stats.TxStats = TxStats{disabled: conn.stats.disabled}
	conn.statsResetTime = time.Now()
	return s, conn.statsResetTime
}

// Close closes the underlying udp socket immediately, unblock all pending
// writes and delete all peers and sessions. Close an closed wireguard have no
// effect.
func (conn *Conn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	conn.stats.RLock()
	defer conn.stats.RUnlock()

	if conn.closed {
		return nil
	}
	conn.closed = true

	conn.logV(3).Print("WireGuard closing...")
	defer conn.logV(3).Print("WireGuard closed")

	peers := make([]*peer, 0)
	conn.peerStore.Range(func(_, v interface{}) bool {
		peers = append(peers, v.(*peer))
		return true
	})
	for _, p := range peers {
		conn.evictPeerLocked(p)
	}

	conn.writeQueue.Close()
	if conn.sharedWrite != nil {
		conn.sharedWrite.Close()
	}
	conn.peerWriters.Range(func(_, v interface{}) bool {
		v.(*PeerWriter).Close()
		return true
	})

	conn.sessionStore.Range(func(k, _ interface{}) bool {
		conn.sessionStore.Delete(k)
		return true
	})
	return conn.transport.Close()
}

// PublicKey returns a clone version of the static public key of the WireGuard
// connection.
func (conn *Conn) PublicKey() Key {
	return *conn.staticPub
}

// PrivateKey returns a clone version of the static private key of the WireGuard
// connection.
func (conn *Conn) PrivateKey() Key {
	return *conn.staticPriv
}

// WriteTo queues a message for a peer identified by its static public key,
// consulting PeerConfigLookup when needed. A successful return confirms queue
// admission, not transmission or delivery. Encryption and sending happen in the
// background; a message can trigger a handshake and be discarded while no
// session is available. Applications must implement retries or acknowledgements
// when delivery matters.
func (conn *Conn) WriteTo(b []byte, staticPubKey Key) (int, Peer, error) {
	if conn.sharedWrite != nil {
		p, ok := conn.peer(staticPubKey)
		if !ok {
			return 0, nil, ErrPeerNotFound
		}
		n, err := conn.sharedWrite.enqueueChunks([][]byte{b}, p)
		return n, p, err
	}
	w := conn.PeerWriter(staticPubKey)
	return w.WriteToPeer(b)
}

// ReadQueue returns a channel that contains all packets received by the
// connection. Users can use this channel to read data from the connection.
func (conn *Conn) ReadQueue() <-chan Packet {
	return conn.readQueue
}

// ReadFrom reads up to len(b) bytes into b. It returns the number of bytes
// read, the corresponding peer and any error encountered. Users can use the
// returned peer to send data back directly. Writing data in this way is more
// efficient than calling WriteTo. If err is nil and n is 0, it means that we
// received an empty packet, e.g. a keep-alive message. Cannot be called
// concurrently.
func (conn *Conn) ReadFrom(b []byte) (int, Peer, error) {
	pkt, ok := <-conn.readQueue
	if !ok {
		return 0, nil, errConnClosed
	}
	defer pkt.Release()
	n := copy(b, pkt.Data)
	if n < len(pkt.Data) {
		return 0, nil, io.ErrShortBuffer
	}
	return n, pkt.From(), nil
}

func (conn *Conn) handleInboundMessage(msg *inboundMessage) ([]byte, error) {
	data, valid := msg.Open()
	conn.stats.RLock()
	conn.stats.recvPacket(len(msg.data), msg.typ)
	if !valid {
		conn.stats.RUnlock()
		return nil, errInvalidPacket
	}
	conn.updateStateAfterRecv(msg, data)
	conn.stats.RUnlock()

	switch msg.typ {
	default:
		panic("there should be no other types of messages")
	case header.CookieReply:
		return nil, nil
	case header.TransportData:
		return data, nil
	case header.Initiation, header.Response:
		if data == nil {
			return nil, nil
		}
		if _, err := conn.transport.WriteTo(data, msg.addr); err != nil {
			e := &ioError{
				Op:  "read",
				Err: fmt.Errorf("handshake error: %w", err),
			}
			if ne, ok := err.(netutils.Error); ok {
				e.IsTimeout = ne.Timeout()
				e.IsTemporary = ne.Temporary()
			}
			return nil, e
		}
		msg.logV(3).Printf("Send %v to %v", header.Type(data), msg.addr)

		conn.stats.RLock()
		if s := msg.session; s != nil {
			conn.stats.sendPacket(len(data), header.Response)
			s.peer.stats.sendPacket(len(data), header.Response)
		} else {
			conn.stats.sendPacket(len(data), header.CookieReply)
		}
		conn.stats.RUnlock()
		return nil, nil
	}
}

// Peer returns the currently active peer instance, or nil if it does not exist.
func (conn *Conn) Peer(peerPubKey Key) (Peer, bool) {
	return conn.peer(peerPubKey)
}

// PeerWriter returns a peer writer. This peer writer
func (conn *Conn) PeerWriter(peerPubKey Key) *PeerWriter {
	if v, ok := conn.peerWriters.Load(peerPubKey); ok {
		return v.(*PeerWriter)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if v, ok := conn.peerWriters.Load(peerPubKey); ok {
		return v.(*PeerWriter)
	}
	pw := &PeerWriter{
		pk:   peerPubKey,
		conn: conn,
	}
	conn.peerWriters.Store(peerPubKey, pw)
	if conn.closed {
		// if connection is closed, the write queue is never used.
		return pw
	}
	pw.sendQueue = conn.writeQueue.newSendQueue(1 << 10)
	return pw
}

func (conn *Conn) updateStateAfterRecv(msg *inboundMessage, data []byte) {
	// This message is not requires any authentication, e.g. we send a cookie
	// reply for handshake initiation/response.
	if msg.session == nil {
		return
	}

	peer := msg.session.peer
	peer.Lock()
	defer peer.Unlock()

	if peer.blocked.Read() {
		return
	}
	// If any events starts, we start the set zero timer.
	peer.startSetZeroTimer()

	if !peer.addrRoamingDisabled {
		// Peer address roaming
		if peer.compareAndSetAddrUpdated(msg.time) {
			msg.logV(3).Printf("Peer roaming: %v->%v", peer.addr, msg.addr)
			peer.addr = msg.addr
		}
	}

	// The entire function updateStateAfterRecv runs under the protection of
	// conn.stats.RLock.
	peer.stats.recvPacket(len(msg.data), msg.typ)
	if !conn.stats.disabled {
		peer.stats.LastSeen = msg.time
		peer.stats.RemoteAddr = peer.addr
	}

	switch msg.typ {
	case header.CookieReply:
		if peer.compareAndSetCookieReplyRecv(msg.time) {
			msg.logV(3).Printf("Save cookie: %0x", data)
			copy(peer.cookie[:], data)
		} else {
			msg.logV(3).Printf("Skip cookie: %0x", data)
		}
		peer.startZeroCookieTimer()
	case header.Initiation:
		peer.compareAndSetHandshakeRecv(msg.time)
		peer.compareAndSetHandshakeSent(msg.time)
		peer.setNextSession(msg.session)
		msg.logV(3).Print("Next session is waiting for transport data message")
	case header.Response:
		if peer.handshake != msg.session {
			msg.logV(0).Print("handshake session not match")
			panic("panic")
		}
		peer.compareAndSetHandshakeRecv(msg.time)
		peer.rotateHandshakeSessionToCurrent()
		msg.logV(3).Print("Handshake complete, rotate to current")
	case header.TransportData:
		if len(data) == 0 {
			msg.logV(3).Print("Keepalive recved")
			peer.compareAndSetKeepaliveRecv(msg.time)
		} else {
			msg.logV(3).Print("Transport data recved")
			sent := maxTime([]time.Time{peer.dataSent, peer.keepaliveSent, peer.handshakeSent})
			if sent.After(peer.dataRecv) {
				peer.compareAndSetFirstDataRecvAfterSent(msg.time)
			}
			peer.compareAndSetDataRecv(msg.time)
			peer.startPassiveKeepaliveTimer()
		}
		if peer.next == msg.session {
			msg.logV(3).Print("Next session recv transport data, rotate to current")
			peer.rotateNextSessionToCurrent()
		} else if peer.current != nil {
			// Current session may be evicted after sending data.
			st := peer.current.Snapshot()
			age := msg.time.Sub(st.establishTime)
			if !peer.handshakeInitiationDisabled && st.isInitiator && age > rejectAfterTime-rekeyTimeout-keepaliveTimeout {
				msg.logV(3).Print("Current session is outdating, try to initiate a handshake")
				go peer.InitiateHandshake()
			}
		}
	}
}

func (conn *Conn) updateStateBeforeDataSent(w *peerWriter) (blocked bool, current *secureSession, addr netip.AddrPort) {
	w.peer.Lock()
	defer w.peer.Unlock()

	if w.peer.blocked.Read() {
		return
	}
	if !w.isKeepalive() {
		w.peer.compareAndSetDataWillSend(w.start)
	}
	if w.peer.current == nil {
		w.logV(3).Print("First writing, try to initiate a handshake")
		if !w.peer.handshakeInitiationDisabled {
			go w.peer.InitiateHandshake()
		}
		return w.peer.blocked.Read(), w.peer.current, w.peer.addr
	}
	st := w.peer.current.Snapshot()
	age := time.Since(st.establishTime)

	switch {
	case st.sendCount > rejectAfterMessages || age > rejectAfterTime:
		w.logV(3).Print("Current session is outdated, evict and try to initate a handshake")
		w.peer.evictCurrentSession()
		if !w.peer.handshakeInitiationDisabled {
			go w.peer.InitiateHandshake()
		}
	case st.sendCount > rekeyAfterMessages || st.isInitiator && age > rekeyAfterTime:
		w.logV(3).Print("Current session is outdating, try to initate a handshake")
		if !w.peer.handshakeInitiationDisabled {
			go w.peer.InitiateHandshake()
		}
	}
	return w.peer.blocked.Read(), w.peer.current, w.peer.addr
}

func (conn *Conn) updateStateAfterDataSent(w *peerWriter) {
	conn.stats.RLock()
	conn.stats.sendPacket(len(w.data), header.TransportData)
	w.peer.stats.sendPacket(len(w.data), header.TransportData)
	conn.stats.RUnlock()

	w.peer.Lock()
	defer w.peer.Unlock()

	if w.isKeepalive() {
		w.peer.compareAndSetKeepaliveSent(w.time)
	} else {
		recv := maxTime([]time.Time{w.peer.dataRecv, w.peer.keepaliveRecv, w.peer.handshakeRecv})
		if recv.After(w.peer.dataSent) {
			w.peer.compareAndSetFirstDataSentAfterRecv(w.time)
		}
		w.peer.compareAndSetDataSent(w.time)
		if !w.peer.handshakeInitiationDisabled && !w.peer.blocked.Read() {
			w.peer.startPassiveHandshakeTimer()
		}
	}
}

func (conn *Conn) updateStateAfterHandshakeInitiationSent(w *initiationWriter) {
	peer := w.session.peer

	conn.stats.RLock()
	conn.stats.sendPacket(header.HandshakeInitiationSize, header.Initiation)
	peer.stats.sendPacket(header.HandshakeInitiationSize, header.Initiation)
	conn.stats.RUnlock()

	peer.Lock()
	defer peer.Unlock()

	peer.compareAndSetHandshakeSent(w.time)
	peer.startSetZeroTimer()
}

func (conn *Conn) getInboundMessage() *inboundMessage {
	msg := inboundMessagePool.Get().(*inboundMessage)
	msg.conn = conn
	msg.buf = bufpool.Get()
	return msg
}

func (conn *Conn) putInboundMessage(msg *inboundMessage) {
	bufpool.Put(msg.buf)
	msg.setZero()
	inboundMessagePool.Put(msg)
}

func (conn *Conn) session(receiver uint32) (*secureSession, bool) {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	if conn.closed {
		return nil, false
	}
	v, ok := conn.sessionStore.Load(receiver)
	if !ok {
		return nil, false
	}
	return v.(*secureSession), true
}

func (conn *Conn) saveSession(s *secureSession) error {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	conn.stats.RLock()
	defer conn.stats.RUnlock()
	return conn.saveSessionLocked(s)
}

// +checklocksread:conn.mu
// +checklocksread:conn.stats.mu
func (conn *Conn) saveSessionLocked(s *secureSession) error {
	if conn.closed {
		return errConnClosed
	}
	for attempts := 0; attempts < 5; attempts++ {
		if err := binary.Read(rand.Reader, binary.LittleEndian, &s.sender); err != nil {
			return err
		}
		if _, loaded := conn.sessionStore.LoadOrStore(s.sender, s); !loaded {
			conn.stats.sessionCreatedLocked()
			break
		}
	}
	return nil
}

func (conn *Conn) deleteSession(s *secureSession) bool {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	_, loaded := conn.sessionStore.LoadAndDelete(s.sender)
	if loaded {
		conn.stats.SessionDeleted()
	}
	return loaded
}

// +checklocksread:conn.mu
// +checklocksread:conn.stats.mu
func (conn *Conn) deleteSessionLocked(s *secureSession) bool {
	_, loaded := conn.sessionStore.LoadAndDelete(s.sender)
	if loaded {
		conn.stats.sessionDeletedLocked()
	}
	return loaded
}

func (conn *Conn) peer(peerPubKey Key) (*peer, bool) {
	conn.mu.RLock()
	defer conn.mu.RUnlock()
	if conn.closed {
		return nil, false
	}
	if peer, existed := conn.loadPeer(peerPubKey); existed {
		return peer, true
	}
	// Reserve before constructing state; release duplicates and lookup failures.
	reserved := conn.peerCount.Add(1)
	keep := false
	defer func() {
		if !keep {
			conn.peerCount.Add(-1)
		}
	}()
	if conn.maxPeers > 0 && reserved > conn.maxPeers {
		return nil, false
	}
	var mk, ck Key
	utils.Hash(mk.Ptr(), []byte(mac1Label), peerPubKey[:])
	utils.Hash(ck.Ptr(), []byte(cookieLabel), peerPubKey[:])
	cipher, err := chacha20poly1305.NewX(ck[:])
	if err != nil {
		logger.Errorf("Failed to new chacha20poly1305: %v", err)
		return nil, false
	}
	p := &peer{
		conn:             conn,
		staticPub:        &peerPubKey,
		mac1GenerateKey:  mk[:],
		cookieOpenCipher: cipher,
	}
	var pi *PeerConfig
	if conn.peerConfigLookup != nil {
		// TODO(#31): retry peer config lookup if error returns.
		var err error
		pi, err = conn.peerConfigLookup(peerPubKey)
		if err != nil {
			return nil, false
		}
	}
	if pi == nil {
		return nil, false
	}
	p.blocked.SetFalse()
	p.addrRoamingDisabled = pi.DisableAddrRoaming
	p.handshakeInitiationDisabled = pi.DisableHandshakeInitiation
	if pi.PSK != nil {
		p.psk.Set(*pi.PSK)
	}
	if pi.Addr.IsValid() {
		p.addr = pi.Addr
	}

	// Lock peer to ensure p.stats is not nil when peer is accessed.
	p.Lock()
	peer, peerExisted := conn.loadOrStorePeer(peerPubKey, p)
	if peerExisted {
		p.Unlock()
		return peer, true
	}
	keep = true
	ps, _ := conn.stats.ensurePeerStats(peerPubKey)
	atomic.StorePointer(&ps.peerPtr, unsafe.Pointer(p))
	p.stats = ps
	p.Unlock()

	conn.stats.RLock()
	if !conn.stats.disabled {
		atomic.AddUint64(&conn.stats.PeersJoin, 1)
	}
	conn.stats.RUnlock()

	return p, true
}

func (conn *Conn) loadPeer(pk Key) (*peer, bool) {
	if v, loaded := conn.peerStore.Load(pk); loaded {
		return v.(*peer), true
	}
	return nil, false
}

func (conn *Conn) loadOrStorePeer(pk Key, p *peer) (*peer, bool) {
	v, loaded := conn.peerStore.LoadOrStore(pk, p)
	return v.(*peer), loaded
}

func (conn *Conn) evictPeer(p *peer) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.stats.RLock()
	defer conn.stats.RUnlock()
	return conn.evictPeerLocked(p)
}

// +checklocksread:conn.mu
// +checklocksread:conn.stats.mu
func (conn *Conn) evictPeerLocked(p *peer) bool {
	_, loaded := conn.peerStore.LoadAndDelete(*p.staticPub)
	if !loaded {
		return false
	}
	conn.peerCount.Add(-1)
	if !conn.stats.disabled {
		atomic.AddUint64(&conn.stats.PeersEvict, 1)
	}
	// After the Peer has been deleted from the peerStore, due to concurrency,
	// the new Peer may be stored in the peerStore. Therefore, when clearing
	// peerPtr, we need to ensure that peerPtr still points to the current
	// peer.
	atomic.CompareAndSwapPointer(&p.stats.peerPtr, unsafe.Pointer(p), nil)

	ss := p.SetZero()
	for _, s := range ss {
		conn.deleteSessionLocked(s)
	}
	p.evicted.SetTrue()
	// blocked is also read non-atomically while holding peer.mu. Eviction
	// must use the same lock as Block/Unblock and the packet workers.
	p.Block()
	return true
}

func (conn *Conn) isUnderLoad() bool { return conn.UnderLoad.AtomicRead() }
