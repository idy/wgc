package wireguard

import (
	"sync"
	"testing"
)

func TestConcurrentReceiveStatistics(t *testing.T) {
	conn := &Conn{staticPub: new(Key)}
	const workers, perWorker = 16, 256
	var wait sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for range perWorker {
				msg := inboundMessage{conn: conn, data: []byte{0}}
				conn.handleInboundMessage(&msg)
			}
		}()
	}
	close(start)
	wait.Wait()
	stats, _ := conn.CaptureStats()
	if stats.PacketsRecv != workers*perWorker || stats.BytesRecv != workers*perWorker {
		t.Fatalf("received counters = %d packets, %d bytes; want %d each", stats.PacketsRecv, stats.BytesRecv, workers*perWorker)
	}
	reset, _ := conn.CaptureStats()
	if reset.PacketsRecv != 0 || reset.BytesRecv != 0 {
		t.Fatal("capture did not reset receive counters")
	}
}
