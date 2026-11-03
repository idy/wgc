package wireguard

import (
	"encoding/base64"
	"testing"
)

func TestKeyFromBase64RejectsInvalidLengths(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		encoded := base64.StdEncoding.EncodeToString(make([]byte, size))
		if _, err := KeyFromBase64(encoded); err == nil {
			t.Errorf("KeyFromBase64 accepted %d decoded bytes", size)
		}
	}
}

func TestKeyFromBase64AcceptsKeySize(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(make([]byte, KeySize))
	if _, err := KeyFromBase64(encoded); err != nil {
		t.Fatalf("KeyFromBase64 returned %v", err)
	}
}
