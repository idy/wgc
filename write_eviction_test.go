package wireguard

import (
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func requireEvictionError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrPeerBlocked) || errors.Is(err, net.ErrClosed) {
		t.Fatalf("eviction error = %v; want ErrPeerBlocked without net.ErrClosed", err)
	}
}

func TestRetiredPeerQueueDoesNotReportConnectionClosed(t *testing.T) {
	for _, shared := range []bool{false, true} {
		name := "dedicated"
		if shared {
			name = "shared"
		}
		t.Run(name, func(t *testing.T) {
			conn, err := NewConn(newChannelTransport(), Config{
				ReadQueueSize:    1,
				WriteQueueSize:   1,
				DisableStats:     true,
				SharedWriteQueue: shared,
				PeerConfigLookup: func(Key) (*PeerConfig, error) {
					return &PeerConfig{DisableHandshakeInitiation: true}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			key := testKey(t)
			_, target, err := conn.WriteTo([]byte("before eviction"), key)
			if err != nil {
				t.Fatal(err)
			}
			p := target.(*peer)
			queue := conn.sharedWrite
			if !shared {
				value, ok := conn.autoWriters.Load(p)
				if !ok {
					t.Fatal("implicit queue not registered")
				}
				queue = value.(*sendQueue)
			}
			if !conn.evictPeer(p) {
				t.Fatal("peer not evicted")
			}
			// A WriteTo fast path can retain this queue before eviction removes it.
			_, err = queue.enqueueChunks([][]byte{[]byte("stale queue")}, p)
			requireEvictionError(t, err)
			if _, _, err := conn.WriteTo([]byte("new peer"), key); err != nil {
				t.Fatalf("connection unusable after peer eviction: %v", err)
			}
			conn.Close()
			if _, err := queue.enqueueChunks(nil, p); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("connection shutdown error = %v; want net.ErrClosed", err)
			}
		})
	}
}

func TestWriteToPeerEvictedBeforeQueueCreation(t *testing.T) {
	key := testKey(t)
	lookedUp := make(chan struct{})
	releaseLookup := make(chan struct{})
	var lookupOnce, releaseOnce sync.Once
	conn, err := NewConn(newChannelTransport(), Config{
		ReadQueueSize:  1,
		WriteQueueSize: 1,
		DisableStats:   true,
		PeerConfigLookup: func(Key) (*PeerConfig, error) {
			lookupOnce.Do(func() {
				close(lookedUp)
				<-releaseLookup
			})
			return &PeerConfig{DisableHandshakeInitiation: true}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	release := func() { releaseOnce.Do(func() { close(releaseLookup) }) }
	defer release()
	result := make(chan error, 1)
	go func() {
		_, _, err := conn.WriteTo([]byte("racing eviction"), key)
		result <- err
	}()
	select {
	case <-lookedUp:
	case <-time.After(3 * time.Second):
		t.Fatal("peer lookup did not start")
	}
	evicted := make(chan bool, 1)
	go func() {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		conn.stats.RLock()
		defer conn.stats.RUnlock()
		p, ok := conn.loadPeer(key)
		evicted <- ok && conn.evictPeerLocked(p)
	}()
	// The lookup holds a read lock. A failed TryRLock proves eviction has
	// claimed the writer lock and will run before WriteTo creates its queue.
	deadline := time.Now().Add(3 * time.Second)
	for conn.mu.TryRLock() {
		conn.mu.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("eviction did not wait for peer admission")
		}
		runtime.Gosched()
	}
	release()
	if !<-evicted {
		t.Fatal("admitted peer was not evicted")
	}
	requireEvictionError(t, <-result)
	if _, _, err := conn.WriteTo([]byte("retry"), key); err != nil {
		t.Fatalf("retry after peer eviction failed: %v", err)
	}
}

func TestWriteToPeerEvictedDuringEnqueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := channelConn(t, newChannelTransport())
		defer conn.Close()
		p, _ := installTransportSession(t, conn)
		key := p.StaticPubKey()
		if _, _, err := conn.WriteTo([]byte("blocked send"), key); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, _, err := conn.WriteTo([]byte("full queue"), key); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		result := make(chan error, 1)
		go func() {
			_, _, err := conn.WriteTo([]byte("waiting enqueue"), key)
			result <- err
		}()
		synctest.Wait()
		if !conn.evictPeer(p) {
			t.Fatal("peer not evicted")
		}
		synctest.Wait()
		requireEvictionError(t, <-result)
		if _, _, err := conn.WriteTo([]byte("retry"), key); err != nil {
			t.Fatalf("connection unusable after retiring blocked queue: %v", err)
		}
	})
}
