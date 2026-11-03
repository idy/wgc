package regression_test

import (
	"testing"

	wireguard "github.com/idy/wgc"
	"github.com/idy/wgc/tests/internal/testutil"
)

func newPassiveConn(t *testing.T) *wireguard.Conn {
	t.Helper()
	return testutil.NewConn(t, wireguard.Config{
		MaxPeers:         2,
		DisableStats:     true,
		SharedWriteQueue: true,
		PeerConfigLookup: func(wireguard.Key) (*wireguard.PeerConfig, error) {
			return &wireguard.PeerConfig{DisableHandshakeInitiation: true}, nil
		},
	})
}

func TestOversizedWritesRejectedBeforeQueueAdmission(t *testing.T) {
	conn := newPassiveConn(t)
	_, key := testutil.Keys(t)
	writer := conn.PeerWriter(key)
	defer writer.Close()
	payload := make([]byte, wireguard.MaximumDataSize+1)
	for _, chunks := range [][][]byte{{payload}, {payload[:wireguard.MaximumDataSize], payload[wireguard.MaximumDataSize:]}} {
		if n, _, err := writer.WriteChunksToPeer(chunks); err == nil || n != 0 {
			t.Errorf("WriteChunksToPeer oversized message = %d, %v", n, err)
		}
	}
	if n, _, err := conn.WriteTo(payload, key); err == nil || n != 0 {
		t.Errorf("WriteTo oversized message = %d, %v", n, err)
	}
	if n, _, err := conn.WriteTo(payload[:wireguard.MaximumDataSize], key); err != nil || n != wireguard.MaximumDataSize {
		t.Errorf("WriteTo maximum message = %d, %v", n, err)
	}
}

func TestPeerWriterCloseAfterConnectionClose(t *testing.T) {
	conn := newPassiveConn(t)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	_, key := testutil.Keys(t)
	writer := conn.PeerWriter(key)
	for range 2 {
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
