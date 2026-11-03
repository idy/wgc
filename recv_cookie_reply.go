package wireguard

import (
	"github.com/idy/wgc/internal/header"
)

type cookieReply inboundMessage

func (r *cookieReply) msg() header.CookieReplyMessage {
	return header.CookieReplyMessage(r.data)
}

func (r *cookieReply) Open() ([]byte, bool) {
	if len(r.data) != header.CookieReplySize {
		r.logV(3).Printf("Invalid cookie reply size")
		return nil, false
	}
	s, ok := r.conn.session(r.msg().Receiver())
	if !ok {
		r.logV(3).Printf("Receiver %d not found: ", r.msg().Receiver())
		return nil, false
	}
	if s.peer.blocked.AtomicRead() {
		r.logV(3).Print("Peer is blocked")
		return nil, false
	}
	r.session = s
	m := r.msg()

	s.RLock()
	mac1 := s.mac1
	s.RUnlock()

	cookie, err := s.peer.cookieOpenCipher.Open(
		m.Cookie()[:0],
		m.Nonce()[:],
		m.Cookie()[:],
		mac1[:],
	)
	if err != nil {
		r.logV(3).Printf("Invalid cookie reply: %v", err)
		return nil, false
	}
	return cookie, true
}
