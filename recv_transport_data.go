package wireguard

import "github.com/idy/wgc/internal/header"

type transportData inboundMessage

func (td *transportData) msg() header.TransportDataMessage {
	return header.TransportDataMessage(td.data)
}

func (td *transportData) Open() ([]byte, bool) {
	if len(td.data) < header.EmptyTransportDataSize {
		td.logV(3).Printf("Invalid transport data size")
		return nil, false
	}
	s, ok := td.conn.session(td.msg().Receiver())
	if !ok {
		td.logV(3).Printf("Receiver %d not found: ", td.msg().Receiver())
		return nil, false
	}
	if s.peer.blocked.AtomicRead() {
		td.logV(3).Print("Peer is blocked")
		return nil, false
	}
	td.session = s

	ss := s.Snapshot()

	switch ss.state {
	default:
		td.logV(3).Printf("Invalid session state: %v", ss.state)
		return nil, false
	case confirmed, responded:
	}
	if td.time.Sub(ss.establishTime) >= rejectAfterTime {
		td.logV(3).Print("Session outdated")
		return nil, false
	}
	m := td.msg()
	m.SetReceiver(0)

	counter := m.Counter()
	if counter >= rejectAfterMessages {
		return nil, false
	}
	b, err := ss.recvCipher.Open(m.Packet()[:0], m.Nonce()[:], m.Packet(), nil)
	if err != nil {
		td.logV(3).Print("Invalid transport data")
		return nil, false
	}
	// Authentication must precede the replay-window mutation: a forged tag
	// must not consume a valid counter or advance the window. Decryption stays
	// parallel; only the shared replay-filter operation is serialized.
	s.Lock()
	valid := s.replayFilter.ValidateCounter(counter, rejectAfterMessages)
	if valid && td.time.After(s.lastRecvTime) {
		s.lastRecvTime = td.time
	}
	s.Unlock()
	if !valid {
		return nil, false
	}
	return b, true
}
