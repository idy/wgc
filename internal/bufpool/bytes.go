//go:build !BUFPOOL_MINI
// +build !BUFPOOL_MINI

package bufpool

import "gvisor.dev/gvisor/pkg/buffer"

const DefaultSize = buffer.MaxChunkSize

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
	return &bytes{buffer.NewViewSize(DefaultSize)}
}

func put(b *bytes) {
	b.view.Release()
}
