package testutil

import (
	"net"
	"testing"
	"time"
)

const IOTimeout = 3 * time.Second

func ListenUDP(tb testing.TB) *net.UDPConn {
	tb.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { socket.Close() })
	if err := socket.SetDeadline(time.Now().Add(IOTimeout)); err != nil {
		tb.Fatal(err)
	}
	return socket
}
