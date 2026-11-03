package wireguard

import (
	"github.com/idy/wgc/internal/header"

	"golang.org/x/crypto/chacha20poly1305"
)

type handshakeResponse inboundMessage

func (hr *handshakeResponse) checkMAC1() bool { return (*inboundMessage)(hr).checkMAC1() }
func (hr *handshakeResponse) checkMAC2() bool { return (*inboundMessage)(hr).checkMAC2() }
func (hr *handshakeResponse) cookieReply() ([]byte, error) {
	return (*inboundMessage)(hr).cookieReply()
}
func (hr *handshakeResponse) msg() header.HandshakeResponseMessage {
	return header.HandshakeResponseMessage(hr.data)
}

func (hr *handshakeResponse) Open() ([]byte, bool) {
	if len(hr.data) != header.HandshakeResponseSize {
		hr.logV(3).Printf("Invalid handshake response size")
		return nil, false
	}
	if !hr.checkMAC1() {
		hr.logV(3).Print("Invalid mac1")
		return nil, false
	}
	if hr.conn.isUnderLoad() && !hr.checkMAC2() {
		hr.logV(3).Print("Invalid mac2, cookie reply")
		r, err := hr.cookieReply()
		if err != nil {
			hr.logV(1).Printf("Failed to gernate cookie reply: %v", err)
			return nil, false
		}
		return r, true
	}
	m := hr.msg()
	s, ok := hr.conn.session(m.Receiver())
	if !ok {
		hr.logV(3).Printf("Receiver %d not found: ", m.Receiver())
		return nil, false
	}
	if s.peer.blocked.AtomicRead() {
		hr.logV(3).Print("Peer is blocked")
		return nil, false
	}
	hr.session = s

	st := s.Snapshot()
	if st.state != initiated || st.hash == nil || st.chainKey == nil || st.ephemeralPriv == nil {
		hr.logV(3).Print("Handshake is not initialized or is already complete")
		return nil, false
	}
	h, ck := *st.hash, *st.chainKey
	hh := newHandshakeHelper(&h, &ck)
	err := hh.ParseHandshakeResponse(
		m,
		st.ephemeralPriv,
		hr.conn.staticPriv,
		s.peer.psk.AtomicRead(),
	)
	if err != nil {
		hr.logV(3).Printf("Failed to parse handshake response: %v", err)
		return nil, false
	}
	sk, rk := hh.KDF2(nil)
	rc, err := chacha20poly1305.New(rk[:])
	if err != nil {
		hr.logV(1).Printf("Failed to derive receive AEAD: %v", err)
		return nil, false
	}
	sc, err := chacha20poly1305.New(sk[:])
	if err != nil {
		hr.logV(1).Printf("New chacha20poly1305 error: %v, key=%0x", err, sk)
		return nil, false
	}

	s.Lock()
	defer s.Unlock()
	// A retransmission can publish a new handshake generation while this
	// response is being authenticated. Commit only the generation we opened.
	if s.state() != initiated || s.hash != st.hash || s.chainKey != st.chainKey || s.ephemeralPriv != st.ephemeralPriv {
		hr.logV(3).Print("Handshake was completed or retransmitted while opening the response")
		return nil, false
	}
	s.receiver = m.Sender()
	s.hash = &h
	s.chainKey = nil
	s.ephemeralPriv = nil
	s.recvCipher = rc
	s.sendCipher = sc
	s.establishTime = hr.time
	return nil, true
}
