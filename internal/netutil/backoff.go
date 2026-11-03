package netutil

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

const (
	backoffMax = 1 * time.Second
	backoffMin = 5 * time.Millisecond
)

type Error interface {
	error
	Timeout() bool
	Temporary() bool
}

type Backoff struct {
	MaxDelay time.Duration
	MinDelay time.Duration

	tempDelay time.Duration
}

func (b *Backoff) maxDelay() time.Duration {
	if b.MaxDelay == 0 {
		return backoffMax
	}
	return b.MaxDelay
}

func (b *Backoff) minDelay() time.Duration {
	if b.MinDelay == 0 {
		return backoffMin
	}
	return b.MinDelay
}

func (b *Backoff) Backoff() time.Duration {
	if b.tempDelay == 0 {
		b.tempDelay = b.minDelay()
	} else {
		b.tempDelay *= 2
	}
	if b.tempDelay > b.maxDelay() {
		b.tempDelay = b.maxDelay()
	}
	return b.tempDelay + TimeJitter()
}

func (b *Backoff) ErrBackoff(err error) (time.Duration, bool) {
	if ne, ok := err.(Error); !ok || !ne.Temporary() {
		return 0, false
	}
	return b.Backoff(), true
}

func (b *Backoff) Reset() {
	b.tempDelay = 0
}

func TimeJitter() time.Duration {
	var v uint16
	binary.Read(rand.Reader, binary.LittleEndian, &v)
	return time.Duration(int64(v)%334) * time.Millisecond
}
