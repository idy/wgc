package integration_test

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	wireguard "github.com/idy/wgc"
	"github.com/idy/wgc/tests/internal/testutil"
	"github.com/idy/wgc/transport"
)

var _ wireguard.Transport = (*transport.UDPConn)(nil)

func TestUDPConnRoundTrip(t *testing.T) {
	left, right := testutil.ListenUDP(t), testutil.ListenUDP(t)
	for _, pair := range [][2]*net.UDPConn{{left, right}, {right, left}} {
		sender, receiver := transport.FromUDPConn(pair[0]), transport.FromUDPConn(pair[1])
		payload := []byte("wgc UDP adapter")
		destination := pair[1].LocalAddr().(*net.UDPAddr).AddrPort()
		if n, err := sender.WriteTo(payload, destination); err != nil || n != len(payload) {
			t.Fatalf("WriteTo = %d, %v", n, err)
		}
		buffer := make([]byte, 64)
		n, source, err := receiver.ReadFrom(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("ReadFrom = %q, %v", buffer[:n], err)
		}
		want := pair[0].LocalAddr().(*net.UDPAddr).AddrPort()
		if source.Port() != want.Port() || source.Addr() != want.Addr().Unmap() || source.Addr().Is4In6() {
			t.Fatalf("sender = %s, want unmapped %s", source, want)
		}
	}
}

func TestUDPConnCloseUnblocksRead(t *testing.T) {
	adapter := transport.FromUDPConn(testutil.ListenUDP(t))
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, _, err := adapter.ReadFrom(make([]byte, 64))
		result <- err
	}()
	<-started
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}
