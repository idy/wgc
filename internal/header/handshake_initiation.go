package header

import (
	"encoding/binary"
)

type HandshakeInitiationMessage []byte

func (msg HandshakeInitiationMessage) Sender() uint32 {
	b := msg[4:]
	return binary.LittleEndian.Uint32(b[:4])
}

func (msg HandshakeInitiationMessage) SetSender(v uint32) {
	b := msg[4:]
	binary.LittleEndian.PutUint32(b, v)
}

func (msg HandshakeInitiationMessage) Ephemeral() *Key {
	return (*Key)(msg[8:])
}

func (msg HandshakeInitiationMessage) SetEphemeral(v []byte) {
	copy(msg.Ephemeral()[:], v)
}

func (msg HandshakeInitiationMessage) Static() *[aeadKeySize]byte {
	return (*[aeadKeySize]byte)(msg[40:])
}

func (msg HandshakeInitiationMessage) Timestamp() *[aeadTAISize]byte {
	return (*[aeadTAISize]byte)(msg[88:])
}

func (msg HandshakeInitiationMessage) MAC1() *[CookieSize]byte {
	return (*[CookieSize]byte)(msg[116:])
}

func (msg HandshakeInitiationMessage) MAC2() *[CookieSize]byte {
	return (*[CookieSize]byte)(msg[132:])
}
