package wireguard

import (
	"testing"
	"time"

	"github.com/idy/wgc/internal/header"
)

func TestLogPrefixes(t *testing.T) {
	t.Cleanup(func() { SetLogHandler(nil) })
	var local, remote Key
	for i := range remote {
		remote[i] = 255
	}
	conn := &Conn{staticPub: &local}
	p := &peer{conn: conn, staticPub: &remote}
	s := &secureSession{peer: p, sender: 17}
	start := time.Unix(0, 0)
	w := &peerWriter{peer: p, data: []byte("abc"), start: start, time: start.Add(2500 * time.Millisecond)}
	iw := &initiationWriter{session: s, start: start, time: start.Add(2500 * time.Millisecond)}
	msg := &inboundMessage{conn: conn, session: s, typ: header.TransportData}
	cases := []struct {
		name   string
		value  logV
		prefix string
	}{
		{"connection", conn.logV(3), "wg_AAAAA"},
		{"peer", p.logV(3), "wg_AAAAA p_/////"},
		{"writer", w.logV(3), "wg_AAAAA p_///// w3:2s"},
		{"initiation", iw.logV(3), "wg_AAAAA p_///// s17 iw:2.50s"},
		{"message", msg.logV(3), "wg_AAAAA p_///// s17 mTransportDataMessage"},
		{"no session", (&inboundMessage{conn: conn}).logV(3), "wg_AAAAA"},
		{"cookie", (*cookieReply)(msg).logV(3), "wg_AAAAA p_///// s17 mTransportDataMessage"},
		{"handshake initiation", (*handshakeInitiation)(msg).logV(3), "wg_AAAAA p_///// s17 mTransportDataMessage"},
		{"handshake response", (*handshakeResponse)(msg).logV(3), "wg_AAAAA p_///// s17 mTransportDataMessage"},
		{"transport", (*transportData)(msg).logV(3), "wg_AAAAA p_///// s17 mTransportDataMessage"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var messages []string
			SetLogHandler(func(level int, message string) {
				if level != 3 {
					t.Errorf("level = %d, want 3", level)
				}
				messages = append(messages, message)
			})
			tc.value.Print("hello")
			tc.value.Printf("value=%d", 7)
			if len(messages) != 2 || messages[0] != tc.prefix+"]hello" || messages[1] != tc.prefix+"] value=7" {
				t.Fatalf("unexpected log messages: %q", messages)
			}
		})
	}
}

func TestLogSuppressedContextIsLazy(t *testing.T) {
	SetLogHandler(nil)
	// None of these incomplete contexts can format a prefix. Suppressed logs
	// must return without dereferencing their keys, peers, or sessions.
	for _, value := range []logV{
		new(Conn).logV(3),
		new(peer).logV(3),
		new(peerWriter).logV(3),
		new(initiationWriter).logV(3),
		new(inboundMessage).logV(3),
	} {
		value.Print("suppressed")
		value.Printf("suppressed %d", 1)
	}
}

func BenchmarkSuppressedPacketLog(b *testing.B) {
	SetLogHandler(nil)
	conn := &Conn{staticPub: new(Key)}
	p := &peer{conn: conn, staticPub: new(Key)}
	msg := &inboundMessage{conn: conn, session: &secureSession{peer: p}, typ: header.TransportData, data: make([]byte, 1024)}
	b.Run("Print", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			msg.logV(3).Print("Transport data recved")
		}
	})
	b.Run("Printf", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			msg.logV(3).Printf("Recved OK(%d)", len(msg.data))
		}
	})
}
