//go:build BUFPOOL_MINI
// +build BUFPOOL_MINI

package bufpool

const (
	DefaultSize  = 1500
	chunkBufSize = 1024
)

type chunk [DefaultSize]byte

var chunkBuf = make(chan *chunk, chunkBufSize)

func init() {
	for i := 0; i < chunkBufSize; i++ {
		chunkBuf <- new(chunk)
	}
}

type bytes struct {
	chunk *chunk
	b     []byte
}

func (b *bytes) Bytes() []byte {
	return b.b
}

func (b *bytes) BytesN(n int) []byte {
	if n > cap(b.b) {
		if b.chunk != nil {
			chunkBuf <- b.chunk
			b.chunk = nil
		}
		b.b = make([]byte, n)
	}
	return b.b[:n]
}

func get() *bytes {
	select {
	case chunk := <-chunkBuf:
		return &bytes{chunk: chunk, b: chunk[:]}
	default:
	}
	b := &bytes{b: make([]byte, DefaultSize)}
	return b
}

func put(b *bytes) {
	if b.chunk != nil {
		chunkBuf <- b.chunk
	}
}
