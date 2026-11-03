package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"hash"
	"io"

	"github.com/idy/wgc/internal/header"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// DH does the Curve25519 point multiplication of private key and public key,
// returning 32 bytes of output.
func DH(privKey, pubKey *header.Key) (*header.Key, error) {
	b, err := curve25519.X25519(privKey[:], pubKey[:])
	if err != nil {
		return nil, err
	}
	return (*header.Key)(b), nil
}

// MustDH does the Curve25519 point multiplication of private key and public key,
// returning 32 bytes of output. Panics if error.
func MustDH(privKey, pubKey *header.Key) *header.Key {
	out, err := DH(privKey, pubKey)
	if err != nil {
		panic(err)
	}
	return out
}

// DHGenerate generates a random Curve25519 private key and derives its
// corresponding public key, returning a pair of 32 bytes values, (private,
// public).
func DHGenerate(sk, pk *header.Key) error {
	if sk.IsZero() {
		if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
			return err
		}
		// https://github.com/WireGuard/wireguard-go/blob/master/device/noise-helpers.go#L79
		sk[0] &= 248
		sk[31] &= 127
		sk[31] |= 64
	}
	b, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	*pk = *(*header.Key)(b)
	return nil
}

// MustDHGenerate generates a random Curve25519 private key and derives its
// corresponding public key, returning a pair of 32 bytes values, (private,
// public). Panics if error.
func MustDHGenerate(sk, pk *header.Key) {
	if err := DHGenerate(sk, pk); err != nil {
		panic(err)
	}
}

// Hash calculates the 256-bits Blake2s hash sum of the inputs, returning 32
// bytes of output.
func Hash(sum *[blake2s.Size]byte, input []byte, inputs ...[]byte) {
	h, _ := blake2s.New256(nil)
	h.Write(input)
	for _, input := range inputs {
		h.Write(input)
	}
	h.Sum(sum[:0])
}

// Mac calculates the 128-bits Blake2s hash sum of the inputs with the key,
// returning 16 bytes of output.
func Mac(mac *[blake2s.Size128]byte, key []byte, input ...[]byte) {
	h, err := blake2s.New128(key[:])
	if err != nil {
		panic(err)
	}
	for _, in := range input {
		h.Write(in)
	}
	h.Sum(mac[:0])
}

// HMac uses the ordinary BLAKE2s hash function in an HMAC construction,
// returning 32 bytes of output.
func HMac(sum, key *header.Key, input ...[]byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key[:])
	for _, in := range input {
		mac.Write(in)
	}
	mac.Sum(sum[:0])
}

// KDF is HKDF function. If t0 is nil, a 32 byte buffer will be allocated.
//
// t0 = Hmac(key, input)
// t1 = Hmac(t0, []byte{0x1})
// t2 = Hmac(t0, t1, []byte{0x2})
// t3 = Hmac(t0, t2, []byte{0x3})
func KDF(t0, key *header.Key, input []byte, t ...*header.Key) {
	if len(t) == 0 {
		return
	}
	if t0 == nil {
		t0 = new(header.Key)
	}
	HMac(t0, key, input)
	HMac(t[0], t0, []byte{0x1})
	for i := 1; i < len(t); i++ {
		HMac(t[i], t0, t[i-1][:], []byte{byte(i + 1)})
	}
}
