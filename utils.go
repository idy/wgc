package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/idy/wgc/internal/tai64"
)

type timestampFilter struct {
	mu sync.Mutex

	// +checkatomic
	t atomic.Value
}

// +checklocksacquire:f.mu
func (f *timestampFilter) Lock() {
	f.mu.Lock()
}

// +checklocksrelease:f.mu
func (f *timestampFilter) Unlock() {
	f.mu.Unlock()
}

func (f *timestampFilter) after(t *tai64.NanoTime) bool {
	l := f.t.Load()
	if l == nil {
		return false
	}
	s := f.t.Load().(*tai64.NanoTime)
	return s.After(t)
}

func (f *timestampFilter) Filter(t *tai64.NanoTime) bool {
	if f.after(t) {
		return false
	}
	f.Lock()
	defer f.Unlock()
	if f.after(t) {
		return false
	}
	v := *t
	f.t.Store(&v)
	return true
}

func maxTime(ts []time.Time) time.Time {
	var l time.Time
	for _, t := range ts {
		if l.Before(t) {
			l = t
		}
	}
	return l
}

func compareAndAssignTime(a *time.Time, b time.Time) bool {
	if a.Before(b) {
		*a = b
		return true
	}
	return false
}

func randomJitter() time.Duration {
	var v uint16
	binary.Read(rand.Reader, binary.LittleEndian, &v)
	return time.Duration(int64(v)%334) * time.Millisecond
}

func addrToBytes(dst []byte, addr netip.AddrPort) []byte {
	n := copy(dst, addr.Addr().AsSlice())
	binary.LittleEndian.PutUint16(dst[n:][:2], addr.Port())
	return dst[:n+2]
}

type ioError struct {
	Err         error  // description of the error
	Op          string // read or write
	Peer        *Key   // peer key, can be empty
	IsTimeout   bool   // if true, timed out; not all timeouts set this
	IsTemporary bool   // if true, error is temporary; not all errors set this
}

func (e *ioError) Timeout() bool   { return e.IsTimeout }
func (e *ioError) Temporary() bool { return e.IsTemporary }
func (e *ioError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var sb strings.Builder
	sb.WriteString(e.Op)
	if e.Peer != nil {
		sb.WriteString(" to ")
		sb.WriteString(e.Peer.String())
	}
	sb.WriteString(" error: ")
	sb.WriteString(e.Err.Error())
	return sb.String()
}

func (e *ioError) Unwrap() error {
	return e.Err
}

type atomicBool struct {
	// +checkatomic
	v int32
}

// +checklocksignore: This method is defined for non-currency usage.
func (b *atomicBool) Read() bool { return b.v != 0 }

func (b *atomicBool) AtomicRead() bool { return atomic.LoadInt32(&b.v) != 0 }
func (b *atomicBool) SetTrue()         { atomic.StoreInt32(&b.v, 1) }
func (b *atomicBool) SetFalse()        { atomic.StoreInt32(&b.v, 0) }

func (b *atomicBool) Set(v bool) {
	if v {
		b.SetTrue()
	} else {
		b.SetFalse()
	}
}

type atomicKey struct {
	// +checkatomic
	v unsafe.Pointer
}

// +checklocksignore: This method is defined for non-currency usage.
func (k *atomicKey) Read() *Key { return (*Key)(k.v) }

func (k *atomicKey) AtomicRead() *Key { return (*Key)(atomic.LoadPointer(&k.v)) }
func (k *atomicKey) Set(v Key)        { atomic.StorePointer(&k.v, unsafe.Pointer(&v)) }
func (k *atomicKey) SetNil()          { atomic.StorePointer(&k.v, nil) }
