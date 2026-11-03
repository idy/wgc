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

// recvPacket does not need to support concurrency, because the ReadFrom
// function does not support concurrency.
func (s *TxStats) recvPacket(n int, typ header.MessageType) {
	if s.disabled {
		return
	}
	s.BytesRecv += uint64(n)
	s.PacketsRecv += 1
	switch typ {
	case header.Initiation:
		s.Handshake.InitiationsRecv += 1
	case header.Response:
		s.Handshake.ResponsesRecv += 1
	case header.CookieReply:
		s.Handshake.CookiesRecv += 1
	}
}

// sendPacket needs to support concurrency because Peer.Write supports
// concurrency.
func (s *TxStats) sendPacket(n int, typ header.MessageType) {
	if s.disabled {
		return
	}
	atomic.AddUint64(&s.BytesSent, uint64(n))
	atomic.AddUint64(&s.PacketsSent, 1)
	switch typ {
	case header.Initiation:
		atomic.AddUint64(&s.Handshake.InitiationsSent, 1)
	case header.Response:
		atomic.AddUint64(&s.Handshake.ResponsesSent, 1)
	case header.CookieReply:
		atomic.AddUint64(&s.Handshake.CookiesSent, 1)
	}
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
		atomic.AddUint64(&cnt.SessionsCreate, 1)
	}
}

func (cnt *statsCounter) SessionDeleted() {
	cnt.RLock()
	defer cnt.RUnlock()
	if !cnt.disabled {
		atomic.AddUint64(&cnt.SessionsDelete, 1)
	}
}

// +checklocksread:cnt.mu
func (cnt *statsCounter) sessionDeletedLocked() {
	if !cnt.disabled {
		atomic.AddUint64(&cnt.SessionsDelete, 1)
	}
}
