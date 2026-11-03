package regression_test

import (
	"bytes"
	"net"
	"runtime"
	"testing"

	"github.com/idy/wgc/tests/internal/testutil"
	"github.com/idy/wgc/transport"
)

func TestUDPConnReadAfterOversizedDatagram(t *testing.T) {
	left, right := testutil.ListenUDP(t), testutil.ListenUDP(t)
	sender, receiver := transport.FromUDPConn(left), transport.FromUDPConn(right)
	destination := right.LocalAddr().(*net.UDPAddr).AddrPort()
	oversized := bytes.Repeat([]byte{0xa5}, 128)
	payload := []byte("next")
	for _, data := range [][]byte{oversized, payload} {
		if n, err := sender.WriteTo(data, destination); err != nil || n != len(data) {
			t.Fatalf("WriteTo = %d, %v; want %d bytes", n, err, len(data))
		}
	}

	buffer := make([]byte, 8)
	n, source, err := receiver.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom after oversized datagram = %v", err)
	}
	if runtime.GOOS != "windows" {
		// Other platforms return the truncated datagram without a socket error.
		if n != len(buffer) || !bytes.Equal(buffer[:n], oversized[:n]) {
			t.Fatalf("truncated datagram = %x, want %x", buffer[:n], oversized[:len(buffer)])
		}
		n, source, err = receiver.ReadFrom(buffer)
		if err != nil {
			t.Fatalf("ReadFrom next datagram = %v", err)
		}
	}
	if !bytes.Equal(buffer[:n], payload) {
		t.Fatalf("ReadFrom = %x, want next payload %x", buffer[:n], payload)
	}
	wantSource := left.LocalAddr().(*net.UDPAddr).AddrPort()
	if source != wantSource || source.Addr().Is4In6() {
		t.Fatalf("source = %s, want unmapped %s", source, wantSource)
	}
}
