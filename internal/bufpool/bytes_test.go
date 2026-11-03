//go:build !BUFPOOL_MINI
// +build !BUFPOOL_MINI

package bufpool

import (
	"runtime"
	"sync"
	"testing"
)

func TestDefaultBufferRetainsOwnedView(t *testing.T) {
	b := Get()
	view := b.view
	if view.Size() != DefaultSize || view.Capacity() != DefaultSize {
		t.Fatalf("view size/capacity = %d/%d, want %d", view.Size(), view.Capacity(), DefaultSize)
	}
	b.Bytes()[0], b.Bytes()[DefaultSize-1] = 17, 29
	Put(b)
	if b.view != nil {
		t.Fatal("returned buffer still owns its pooled view")
	}
	if view.Size() != DefaultSize || view.Capacity() != DefaultSize {
		t.Fatal("normal view was released instead of retained")
	}
	if view.AsSlice()[0] != 17 || view.AsSlice()[DefaultSize-1] != 29 {
		t.Fatal("returning a normal view cleared its contents")
	}
}

func TestDefaultBufferGrowthAndRelease(t *testing.T) {
	b := Get()
	b.Bytes()[0], b.Bytes()[DefaultSize-1] = 17, 29
	if got := b.BytesN(7); len(got) != 7 || len(b.Bytes()) != DefaultSize {
		t.Fatal("requesting a shorter slice changed the view size")
	}
	grown := b.BytesN(DefaultSize + 1)
	if len(grown) != DefaultSize+1 || grown[0] != 17 || grown[DefaultSize-1] != 29 {
		t.Fatal("growing the view lost its existing bytes")
	}
	grown[DefaultSize] = 41
	if got := b.BytesN(DefaultSize + 3); got[DefaultSize] != 41 || len(b.Bytes()) != DefaultSize+3 {
		t.Fatal("growing the view again lost its contents or size")
	}
	view := b.view
	Put(b)
	if view.Size() != 0 || b.view != nil {
		t.Fatal("grown view was retained instead of released")
	}
	next := Get()
	defer Put(next)
	if len(next.Bytes()) != DefaultSize || cap(next.Bytes()) != DefaultSize {
		t.Fatal("grown view changed the next buffer's default size or capacity")
	}
}

func TestDefaultBuffersHaveExclusiveOwnership(t *testing.T) {
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

func BenchmarkDefaultBufferGetPut(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		buf := Get()
		buf.BytesN(64)[0] = 1
		Put(buf)
	}
}
