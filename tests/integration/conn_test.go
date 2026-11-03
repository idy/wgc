package integration_test

import (
	"bytes"
	"testing"

	wireguard "github.com/idy/wgc"
	"github.com/idy/wgc/tests/internal/testutil"
)

func TestEncryptedUDPEcho(t *testing.T) {
	for _, withPSK := range []bool{false, true} {
		name := "without_psk"
		if withPSK {
			name = "with_psk"
		}
		t.Run(name, func(t *testing.T) {
			var psk *wireguard.Key
			if withPSK {
				key, _ := testutil.Keys(t)
				psk = &key
			}
			pair := testutil.NewPair(t, psk)
			for _, size := range []int{1, 64, 1024} {
				payload := bytes.Repeat([]byte{byte(size)}, size)
				if n, _, err := pair.Left.WriteTo(payload, pair.Right.PublicKey()); err != nil || n != len(payload) {
					t.Fatalf("WriteTo = %d, %v", n, err)
				}
				data, sender := testutil.ReadPayload(t, pair.Right)
				if !bytes.Equal(data, payload) || sender.StaticPubKey() != pair.Left.PublicKey() {
					t.Fatal("server received an incorrect payload or authenticated sender")
				}
				writer := sender.Writer()
				if n, err := writer.Write(data); err != nil || n != len(data) {
					t.Fatalf("peer writer = %d, %v", n, err)
				}
				echo, sender := testutil.ReadPayload(t, pair.Left)
				if !bytes.Equal(echo, payload) || sender.StaticPubKey() != pair.Right.PublicKey() {
					t.Fatal("client received an incorrect echo or authenticated sender")
				}
			}
		})
	}
}
