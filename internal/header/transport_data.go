package header

import (
	"encoding/binary"
)

type TransportDataMessage []byte

func (msg TransportDataMessage) Receiver() uint32 {
	b := msg[4:]
	return binary.LittleEndian.Uint32(b[:4])
}

func (msg TransportDataMessage) SetReceiver(v uint32) {
	b := msg[4:]
	binary.LittleEndian.PutUint32(b[:4], v)
}

func (msg TransportDataMessage) Counter() uint64 {
	b := msg[8:]
	return binary.LittleEndian.Uint64(b[:counterSize])
}

func (msg TransportDataMessage) Nonce() *[12]byte {
	return (*[12]byte)(msg[4:])
}

func (msg TransportDataMessage) SetCounter(v uint64) {
	b := msg[8:]
	binary.LittleEndian.PutUint64(b[:counterSize], v)
}

func (msg TransportDataMessage) Packet() []byte {
	return msg[16:]
}
