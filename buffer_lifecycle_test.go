package wireguard

import (
	"bytes"
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/idy/wgc/internal/header"
)

func TestQueuedBufferOwnershipAcrossClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tr := newChannelTransport()
		conn := channelConn(t, tr)
		defer conn.Close()
		p, _ := installTransportSession(t, conn)
		// Loop encrypted datagrams back through the same authenticated session.
		// Unlike UDP, this transport can carry the full MaximumMessageSize.
		p.current.mu.Lock()
		p.current.receiver = 7
		p.current.mu.Unlock()
		writer := p.Writer()
		defer writer.Close()

		roundTrip := func(size int, chunked bool) Packet {
			t.Helper()
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i + size)
			}
			want := bytes.Clone(payload)
			var n int
			var err error
			if chunked {
				mid := len(payload) / 2
				n, err = writer.WriteChunks([][]byte{payload[:mid], payload[mid:]})
			} else {
				n, err = writer.Write(payload)
			}
			if err != nil || n != size {
				t.Fatalf("write %d bytes = %d, %v", size, n, err)
			}
			// The queue must own a copy before Write returns.
			clear(payload)
			synctest.Wait()
			var datagram channelDatagram
			select {
			case datagram = <-tr.outgoing:
			default:
				t.Fatal("queued write did not reach the transport")
			}
			if len(datagram.data) != size+header.EmptyTransportDataSize {
				t.Fatalf("encrypted datagram length = %d, want %d", len(datagram.data), size+header.EmptyTransportDataSize)
			}
			datagram.addr = netip.MustParseAddrPort("127.0.0.1:51820")
			tr.incoming <- datagram
			synctest.Wait()
			select {
			case packet := <-conn.ReadQueue():
				if !bytes.Equal(packet.Data, want) {
					packet.Release()
					t.Fatalf("authenticated %d-byte payload changed", size)
				}
				return packet
			default:
				t.Fatal("authenticated payload did not reach the read queue")
				return Packet{}
			}
		}

		held := roundTrip(MaximumDataSize, true)
		defer held.Release()
		want := bytes.Clone(held.Data)
		for _, size := range []int{1, MaximumDataSize, 64, MaximumDataSize} {
			packet := roundTrip(size, false)
			packet.Release()
			if !bytes.Equal(held.Data, want) {
				t.Fatal("an unreleased packet was reused by another message")
			}
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !bytes.Equal(held.Data, want) {
			t.Fatal("closing the connection invalidated an application-owned packet")
		}
	})
}
