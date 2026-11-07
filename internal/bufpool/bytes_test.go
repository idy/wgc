package bufpool

import (
	"runtime"
	"slices"
	"sync"
	"testing"
)

func TestBufferReleasesOwnership(t *testing.T) {
	b := Get()
	data := b.Bytes()
	if len(data) != DefaultSize || cap(data) != DefaultSize {
		t.Fatalf("buffer size/capacity = %d/%d, want %d", len(data), cap(data), DefaultSize)
	}
	data[0], data[DefaultSize-1] = 17, 29
	Put(b)
	if b.bytes != nil {
		t.Fatal("returned buffer still owns its pooled storage")
	}
	if data[0] != 17 || data[DefaultSize-1] != 29 {
		t.Fatal("returning a normal buffer cleared its contents")
	}
}

func TestBufferGrowthAndRelease(t *testing.T) {
	b := Get()
	b.Bytes()[0], b.Bytes()[DefaultSize-1] = 17, 29
	if got := b.BytesN(7); len(got) != 7 || len(b.Bytes()) != DefaultSize {
		t.Fatal("requesting a shorter slice changed the buffer size")
	}
	grown := b.BytesN(DefaultSize + 1)
	if len(grown) != DefaultSize+1 || grown[0] != 17 || grown[DefaultSize-1] != 29 {
		t.Fatal("growing the buffer lost its existing bytes")
	}
	grown[DefaultSize] = 41
	if got := b.BytesN(DefaultSize + 3); got[DefaultSize] != 41 || len(b.Bytes()) != DefaultSize+3 {
		t.Fatal("growing the buffer again lost its contents or size")
	}
	storage := b.bytes
	Put(b)
	if storage.b != nil || b.bytes != nil {
		t.Fatal("grown buffer was retained instead of released")
	}
	next := Get()
	defer Put(next)
	if len(next.Bytes()) != DefaultSize || cap(next.Bytes()) != DefaultSize {
		t.Fatal("grown buffer changed the next buffer's default size or capacity")
	}
}

func TestBufferWriteAtAcrossCapacity(t *testing.T) {
	b := Get()
	defer Put(b)
	prefix := make([]byte, DefaultSize)
	for i := range prefix {
		prefix[i] = byte(i)
	}
	b.Write(prefix)
	suffix := []byte("continued")
	if n, err := b.WriteAt(suffix, len(prefix)); err != nil || n != len(suffix) {
		t.Fatalf("WriteAt = %d, %v", n, err)
	}
	want := append(prefix, suffix...)
	if !slices.Equal(b.Bytes(), want) {
		t.Fatal("writing beyond the initial capacity lost earlier bytes")
	}
}

func TestBuffersHaveExclusiveOwnership(t *testing.T) {
	var workers sync.WaitGroup
	for id := range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 32 {
				b := Get()
				data := b.BytesN(128)
				for i := range data {
					data[i] = byte(id)
				}
				runtime.Gosched()
				for _, value := range data {
					if value != byte(id) {
						t.Errorf("buffer was shared with another owner: got %d, want %d", value, id)
						break
					}
				}
				Put(b)
			}
		}()
	}
	workers.Wait()
}

func BenchmarkBufferGetPut(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := Get()
		buf.BytesN(64)[0] = 1
		Put(buf)
	}
}
