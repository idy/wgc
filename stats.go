package wireguard

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/idy/wgc/internal/header"
)

// ConnStats is a struct that contains WireGuard connection status.
type ConnStats struct {
	// +checkatomic
	PeersJoin uint64

	// +checkatomic
	PeersEvict uint64

	// +checkatomic
	SessionsCreate uint64

	// +checkatomic
	SessionsDelete uint64
}

// PeerStats is a struct that contains the internal status of a WireGuard Peer.
type PeerStats struct {
	TxStats
	LastSeen   time.Time
	RemoteAddr netip.AddrPort

	// +checkatomic
	peerPtr unsafe.Pointer
}

// TxStats is a struct that records the transmission status.
type TxStats struct {
	disabled    bool
	BytesRecv   uint64
	PacketsRecv uint64

	// +checkatomic
	BytesSent uint64

	// +checkatomic
	PacketsSent uint64

	Handshake struct {
		InitiationsRecv uint64
		ResponsesRecv   uint64
		CookiesRecv     uint64

		// +checkatomic
		InitiationsSent uint64

		// +checkatomic
		ResponsesSent uint64

		// +checkatomic
		CookiesSent uint64
	}
}

var statCounterMu sync.Mutex

// Primitive 64-bit atomics require alignment that ordinary counters do not
// have on 32-bit systems. The enclosing statistics lock still protects captures.
func addStatCounter(counter *uint64, delta uint64) {
	if unsafe.Alignof(uint64(0)) < 8 {
		statCounterMu.Lock()
		*counter += delta
		statCounterMu.Unlock()
		return
	}
	atomic.AddUint64(counter, delta)
}

// addPacketStatCounters updates one packet's counters under a single lock on
// 32-bit systems, retaining atomic updates on systems with 64-bit alignment.
func addPacketStatCounters(bytes, packets, handshake *uint64, n uint64) {
	if unsafe.Alignof(uint64(0)) < 8 {
		statCounterMu.Lock()
		*bytes += n
		*packets += 1
		if handshake != nil {
			*handshake += 1
		}
		statCounterMu.Unlock()
		return
	}
	atomic.AddUint64(bytes, n)
	atomic.AddUint64(packets, 1)
	if handshake != nil {
		atomic.AddUint64(handshake, 1)
	}
}

// Receive counters are updated by parallel decryption workers.
func (s *TxStats) recvPacket(n int, typ header.MessageType) {
	if s.disabled {
		return
	}
	var handshake *uint64
	switch typ {
	case header.Initiation:
		handshake = &s.Handshake.InitiationsRecv
	case header.Response:
		handshake = &s.Handshake.ResponsesRecv
	case header.CookieReply:
		handshake = &s.Handshake.CookiesRecv
	}
	addPacketStatCounters(&s.BytesRecv, &s.PacketsRecv, handshake, uint64(n))
}

// sendPacket needs to support concurrency because Peer.Write supports
// concurrency.
func (s *TxStats) sendPacket(n int, typ header.MessageType) {
	if s.disabled {
		return
	}
	var handshake *uint64
	switch typ {
	case header.Initiation:
		handshake = &s.Handshake.InitiationsSent
	case header.Response:
		handshake = &s.Handshake.ResponsesSent
	case header.CookieReply:
		handshake = &s.Handshake.CookiesSent
	}
	addPacketStatCounters(&s.BytesSent, &s.PacketsSent, handshake, uint64(n))
}

type statsCounter struct {
	disabled bool
	// This mutex is for atomic updates without using exclusive locks when the
	// state is frequently modified, and supports reading multiple values of the
	// same snapshot.
	//
	// Therefore, Lock should be used to read multiple values of the same
	// snapshot, and RLock should be used to protect code segments that modify
	// the state. If you need to read and write in parallel, you should also use
	// atomic operations.
	mu sync.RWMutex

	// +checklocks:mu
	TxStats
	// +checklocks:mu
	ConnStats
	peers sync.Map
}

// +checklocksacquireread:cnt.mu
func (cnt *statsCounter) RLock() {
	cnt.mu.RLock()
}

// +checklocksreleaseread:cnt.mu
func (cnt *statsCounter) RUnlock() {
	cnt.mu.RUnlock()
}

// +checklocksacquire:cnt.mu
func (cnt *statsCounter) Lock() {
	cnt.mu.Lock()
}

// +checklocksrelease:cnt.mu
func (cnt *statsCounter) Unlock() {
	cnt.mu.Unlock()
}

func (cnt *statsCounter) ensurePeerStats(pk Key) (*PeerStats, bool) {
	if cnt.disabled {
		return &PeerStats{TxStats: TxStats{disabled: true}}, false
	}
	v, loaded := cnt.peers.LoadOrStore(pk, new(PeerStats))
	return v.(*PeerStats), loaded
}

func (cnt *statsCounter) SessionCreated() {
	cnt.RLock()
	defer cnt.RUnlock()
	cnt.sessionCreatedLocked()
}

// +checklocksread:cnt.mu
func (cnt *statsCounter) sessionCreatedLocked() {
	if !cnt.disabled {
		addStatCounter(&cnt.SessionsCreate, 1)
	}
}

func (cnt *statsCounter) SessionDeleted() {
	cnt.RLock()
	defer cnt.RUnlock()
	cnt.sessionDeletedLocked()
}

// +checklocksread:cnt.mu
func (cnt *statsCounter) sessionDeletedLocked() {
	if !cnt.disabled {
		addStatCounter(&cnt.SessionsDelete, 1)
	}
}
