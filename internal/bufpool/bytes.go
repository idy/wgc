//go:build !BUFPOOL_MINI
// +build !BUFPOOL_MINI

package bufpool

import "sync"

// Keep the original maximum message size, including transport header and tag.
const DefaultSize = 64 << 10

// Buffers are exclusively owned. Retain normal storage without clearing it on
// reuse, and let the GC reclaim exceptional allocations larger than DefaultSize.
var defaultBuffers = sync.Pool{
	New: func() any { return &bytes{b: make([]byte, DefaultSize)} },
}

type bytes struct {
	b []byte
}

func (b *bytes) Bytes() []byte {
	return b.b
}

func (b *bytes) BytesN(n int) []byte {
	if n > cap(b.b) {
		grown := make([]byte, n)
		copy(grown, b.b)
		b.b = grown
	} else if n > len(b.b) {
		b.b = b.b[:n]
	}
	return b.b[:n]
}

func get() *bytes {
	return defaultBuffers.Get().(*bytes)
}

func put(b *bytes) {
	if len(b.b) == DefaultSize && cap(b.b) == DefaultSize {
		defaultBuffers.Put(b)
	} else {
		b.b = nil
	}
}
