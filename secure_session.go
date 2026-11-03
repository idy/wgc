package wireguard

import (
	"crypto/cipher"
	"strconv"
	"sync"
	"time"

	"github.com/idy/wgc/internal/header"

	"golang.org/x/crypto/blake2s"
	"golang.zx2c4.com/wireguard/replay"
)

type secureSessionState int

const (
	_ secureSessionState = iota
	initiated
	responded
	confirmed
)

func (s secureSessionState) String() string {
	switch s {
	case initiated:
		return "initiated"
	case responded:
		return "responded"
	case confirmed:
		return "confirmed"
	}
	return strconv.Itoa(int(s))
}

type sessionSnapshot struct {
	isInitiator   bool
	receiver      uint32
	sendCount     uint64
	recvCipher    cipher.AEAD
	sendCipher    cipher.AEAD
	establishTime time.Time
	state         secureSessionState

	hash          *[blake2s.Size]byte
	chainKey      *Key
	ephemeralPriv *Key

	lastRecvTime time.Time
}

type secureSession struct {
	// Parallel decrypt workers share this filter. Commit counters only after
	// authentication, while holding mu; replay.Filter is not concurrency-safe.
	// +checklocks:mu
	replayFilter replay.Filter

	isInitiator bool

	peer   *peer
	sender uint32

	mu sync.RWMutex

	// +checklocks:mu
	receiver uint32

	// +checklocks:mu
	hash *[blake2s.Size]byte

	// +checklocks:mu
	chainKey *Key

	// +checklocks:mu
	ephemeralPriv *Key

	// +checklocks:mu
	sendCount uint64

	// +checklocks:mu
	sendCipher cipher.AEAD

	// +checklocks:mu
	recvCipher cipher.AEAD

	// +checklocks:mu
	establishTime time.Time

	// +checklocks:mu
	lastRecvTime time.Time

	// mac1 stores the mac1 used to calculate the last cookie reply message.
	// It's used to verify the mac2 of subsequent received messages.
	// +checklocks:mu
	mac1 [header.CookieSize]byte
}

// +checklocksacquireread:s.mu
func (s *secureSession) RLock() {
	s.mu.RLock()
}

// +checklocksreleaseread:s.mu
func (s *secureSession) RUnlock() {
	s.mu.RUnlock()
}

// +checklocksacquire:s.mu
func (s *secureSession) Lock() {
	s.mu.Lock()
}

// +checklocksrelease:s.mu
func (s *secureSession) Unlock() {
	s.mu.Unlock()
}

// +checklocksread:s.mu
func (s *secureSession) state() (_ secureSessionState) {
	if s.isInitiator {
		if s.establishTime.IsZero() {
			return initiated
		}
		return confirmed
	}
	if s.establishTime.IsZero() {
		return
	}
	if s.lastRecvTime.IsZero() {
		return responded
	}
	return confirmed
}

func (s *secureSession) TxSnapshot() sessionSnapshot {
	s.Lock()
	defer s.Unlock()
	snap := s.snapshot()
	if s.sendCount <= rejectAfterMessages {
		s.sendCount += 1
	}
	return snap
}

func (s *secureSession) Snapshot() sessionSnapshot {
	s.RLock()
	defer s.RUnlock()
	return s.snapshot()
}

// +checklocksread:s.mu
func (s *secureSession) snapshot() sessionSnapshot {
	return sessionSnapshot{
		isInitiator:   s.isInitiator,
		receiver:      s.receiver,
		sendCount:     s.sendCount,
		sendCipher:    s.sendCipher,
		recvCipher:    s.recvCipher,
		state:         s.state(),
		establishTime: s.establishTime,
		lastRecvTime:  s.lastRecvTime,
		hash:          s.hash,
		chainKey:      s.chainKey,
		ephemeralPriv: s.ephemeralPriv,
	}
}
