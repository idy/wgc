package bufpool

type Buffer struct {
	*bytes
}

func (b *Buffer) Write(p []byte) (int, error) {
	return copy(b.BytesN(len(p)), p), nil
}

func (b *Buffer) WriteAt(p []byte, off int) (int, error) {
	return copy(b.BytesN(off + len(p))[off:], p), nil
}

func Get() *Buffer {
	return &Buffer{get()}
}

func Put(b *Buffer) {
	storage := b.bytes
	b.bytes = nil
	put(storage)
}
