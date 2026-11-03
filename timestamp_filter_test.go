package wireguard

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idy/wgc/internal/tai64"
)

func TestInitiationTimestampFilterStrictFreshness(t *testing.T) {
	var filter timestampFilter
	older := tai64.FromTime(time.Unix(100, 0))
	newer := tai64.FromTime(time.Unix(101, 0))
	if filter.isCurrent(&older) {
		t.Fatal("empty filter has a current timestamp")
	}
	if !filter.Filter(&older) || !filter.isCurrent(&older) {
		t.Fatal("first timestamp was not accepted")
	}
	if filter.Filter(&older) {
		t.Fatal("equal timestamp was accepted")
	}
	if !filter.Filter(&newer) || !filter.isCurrent(&newer) || filter.isCurrent(&older) {
		t.Fatal("newer timestamp did not replace the current timestamp")
	}
	if filter.Filter(&older) {
		t.Fatal("older timestamp was accepted")
	}
}

func TestTimestampFilterConcurrentDuplicates(t *testing.T) {
	var filter timestampFilter
	stamp := tai64.FromTime(time.Now())
	const workers = 32
	var accepted atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if filter.Filter(&stamp) {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted identical timestamp %d times", got)
	}
}
