package header

import (
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

type HandshakeResponseMessage []byte

func (msg HandshakeResponseMessage) Sender() uint32 {
	b := msg[4:]
	return binary.LittleEndian.Uint32(b[:4])
}

func (msg HandshakeResponseMessage) SetSender(v uint32) {
	b := msg[4:]
	binary.LittleEndian.PutUint32(b, v)
}

func (msg HandshakeResponseMessage) Receiver() uint32 {
	b := msg[8:]
	return binary.LittleEndian.Uint32(b[:4])
}

func (msg HandshakeResponseMessage) SetReceiver(v uint32) {
	b := msg[8:]
	binary.LittleEndian.PutUint32(b, v)
}

func (msg HandshakeResponseMessage) Ephemeral() *Key {
	return (*Key)(msg[12:])
}

func (msg HandshakeResponseMessage) SetEphemeral(v []byte) {
	b := msg[12:]
	copy(b[:chacha20poly1305.KeySize], v)
}

func (msg HandshakeResponseMessage) Empty() *[aeadTagSize]byte {
	return (*[aeadTagSize]byte)(msg[44:])
}
