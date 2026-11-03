package header

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

type CookieReplyMessage []byte

func (msg CookieReplyMessage) Receiver() uint32 {
	b := msg[4:]
	return binary.LittleEndian.Uint32(b[:4])
}

const xaeadNonceSize = chacha20poly1305.NonceSizeX

func (msg CookieReplyMessage) Nonce() *[xaeadNonceSize]byte {
	return (*[xaeadNonceSize]byte)(msg[8:])
}

func (msg CookieReplyMessage) Cookie() *[aeadCookieSize]byte {
	return (*[aeadCookieSize]byte)(msg[32:])
}

func (msg CookieReplyMessage) SetCookie(v []byte) {
	copy(msg.Cookie()[:], v)
}
