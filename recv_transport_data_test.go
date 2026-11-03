package wireguard

import (
	"bytes"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idy/wgc/internal/header"
	"golang.org/x/crypto/chacha20poly1305"
)

func transportReceiver(t *testing.T) (*Conn, func(uint64) *transportData) {
	t.Helper()
	cipher, err := chacha20poly1305.New(make([]byte, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	conn := &Conn{staticPub: new(Key)}
	session := &secureSession{peer: &peer{conn: conn, staticPub: new(Key)}, isInitiator: true, establishTime: time.Now(), recvCipher: cipher}
	const receiver = 7
	conn.sessionStore.Store(uint32(receiver), session)
	return conn, func(counter uint64) *transportData {
		plain := []byte("authenticated transport payload")
		message := make(header.TransportDataMessage, header.EmptyTransportDataSize+len(plain))
		header.SetType(message, header.TransportData)
		message.SetCounter(counter)
		cipher.Seal(message.Packet()[:0], message.Nonce()[:], plain, nil)
		message.SetReceiver(receiver)
		return &transportData{conn: conn, time: time.Now(), data: message, typ: header.TransportData}
	}
}

func TestTransportDataUnauthenticatedCounterDoesNotConsumeWindow(t *testing.T) {
	for _, forgedCounter := range []uint64{0, 1 << 20} {
		t.Run(strconv.FormatUint(forgedCounter, 10), func(t *testing.T) {
			conn, packet := transportReceiver(t)
			bad := packet(forgedCounter)
			bad.data[len(bad.data)-1] ^= 1
			if _, accepted := bad.Open(); accepted {
				t.Fatal("unauthenticated packet accepted")
			}
			session, _ := conn.session(7)
			if !session.Snapshot().lastRecvTime.IsZero() {
				t.Fatal("unauthenticated packet refreshed receive activity")
			}
			if data, accepted := packet(0).Open(); !accepted || !bytes.Equal(data, []byte("authenticated transport payload")) {
				t.Fatal("unauthenticated counter discarded a subsequent valid packet")
			}
		})
	}
}

func TestTransportDataReplayCannotRefreshActivity(t *testing.T) {
	conn, packet := transportReceiver(t)
	first := packet(0)
	if _, accepted := first.Open(); !accepted {
		t.Fatal("authenticated packet rejected")
	}
	session, _ := conn.session(7)
	replay := packet(0)
	replay.time = first.time.Add(time.Minute)
	if _, accepted := replay.Open(); accepted {
		t.Fatal("replayed packet accepted")
	}
	if !session.Snapshot().lastRecvTime.Equal(first.time) {
		t.Fatal("replayed packet refreshed receive activity")
	}
	older := packet(1)
	older.time = first.time.Add(-time.Millisecond)
	if _, accepted := older.Open(); !accepted || !session.Snapshot().lastRecvTime.Equal(first.time) {
		t.Fatal("parallel receive order moved authenticated activity backwards")
	}
}

func TestTransportDataConcurrentAuthenticationAndReplay(t *testing.T) {
	_, packet := transportReceiver(t)
	const workers, perWorker = 16, 256
	start := make(chan struct{})
	var wait sync.WaitGroup
	var rejected atomic.Int64
	for worker := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for i := range perWorker {
				if _, accepted := packet(uint64(i*workers + worker)).Open(); !accepted {
					rejected.Add(1)
				}
			}
		}()
	}
	close(start)
	wait.Wait()
	if n := rejected.Load(); n != 0 {
		t.Fatalf("discarded %d unique authenticated packets", n)
	}
	for counter := range uint64(workers * perWorker) {
		if _, accepted := packet(counter).Open(); accepted {
			t.Fatalf("accepted duplicate authenticated counter %d", counter)
		}
	}
}

func TestTransportDataConcurrentDuplicateAcceptedOnce(t *testing.T) {
	_, packet := transportReceiver(t)
	const workers = 32
	start := make(chan struct{})
	var wait sync.WaitGroup
	var accepted atomic.Int64
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if _, ok := packet(42).Open(); ok {
				accepted.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if n := accepted.Load(); n != 1 {
		t.Fatalf("accepted the same authenticated counter %d times", n)
	}
}
