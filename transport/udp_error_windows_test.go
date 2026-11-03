package transport

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsDatagramTooLarge(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "success"},
		{name: "message too large", err: windows.WSAEMSGSIZE, want: true},
		{
			name: "wrapped message too large",
			err:  &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("WSARecvFrom", windows.WSAEMSGSIZE)},
			want: true,
		},
		{
			name: "other socket error",
			err:  &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("WSARecvFrom", windows.WSAECONNRESET)},
		},
		{name: "closed", err: net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDatagramTooLarge(tc.err); got != tc.want {
				t.Fatalf("isDatagramTooLarge(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
