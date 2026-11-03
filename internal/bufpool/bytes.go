//go:build !BUFPOOL_MINI
// +build !BUFPOOL_MINI

package bufpool

import (
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
)

const DefaultSize = buffer.MaxChunkSize

// Views are exclusively owned and never cloned. Retaining a normal view avoids
// gVisor clearing its entire chunk when it is acquired again.
var defaultViews = sync.Pool{
	New: func() any { return buffer.NewViewSize(DefaultSize) },
}

type bytes struct {
	view *buffer.View
}

func (b *bytes) Bytes() []byte {
	return b.view.AsSlice()
}

func (b *bytes) BytesN(n int) []byte {
	m := n - b.view.Size()
	if m > 0 {
		b.view.Grow(m)
	}
	return b.view.AsSlice()[:n]
}

func get() *bytes {
	return &bytes{view: defaultViews.Get().(*buffer.View)}
}

func put(b *bytes) {
	view := b.view
	b.view = nil
	if view.Size() == DefaultSize && view.Capacity() == DefaultSize {
		defaultViews.Put(view)
	} else {
		view.Release()
	}
}
