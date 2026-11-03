package tai64

import (
	"bytes"
	"encoding/binary"
	"time"
)

const NanoSize = 12

type NanoTime [NanoSize]byte

const (
	// 0x4000000000000000 is the base seconds TAI used to present 1970.1.1, and 0xa
	// is the initial 10 seconds offset between TAI and Unix epoch. About TAI, see:
	// https://cr.yp.to/libtai/tai64.html. About the 10 seconds offset, see:
	// https://en.wikipedia.org/wiki/International_Atomic_Time
	baseSec = int64(0x400000000000000a)

	whitenerMask = ^uint32(0xffffff)
)

func FromTime(t time.Time) NanoTime {
	var b [NanoSize]byte
	binary.BigEndian.PutUint64(b[:8], uint64(baseSec+t.Unix()))
	binary.BigEndian.PutUint32(b[8:], uint32(t.Nanosecond())&whitenerMask)
	return NanoTime(b)
}

func (t *NanoTime) After(v *NanoTime) bool {
	return bytes.Compare(t[:], v[:]) > 0
}

func (t *NanoTime) Before(v *NanoTime) bool {
	return bytes.Compare(t[:], v[:]) < 0
}

func (t *NanoTime) Equal(v *NanoTime) bool {
	return bytes.Equal(t[:], v[:])
}
