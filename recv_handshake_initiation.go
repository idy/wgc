package wireguard

import (
	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/utils"

	"golang.org/x/crypto/chacha20poly1305"
)

type handshakeInitiation inboundMessage

func (hi *handshakeInitiation) checkMAC1() bool { return (*inboundMessage)(hi).checkMAC1() }
func (hi *handshakeInitiation) checkMAC2() bool { return (*inboundMessage)(hi).checkMAC2() }
func (hi *handshakeInitiation) cookieReply() ([]byte, error) {
	return (*inboundMessage)(hi).cookieReply()
}
func (hi *handshakeInitiation) msg() header.HandshakeInitiationMessage {
	return header.HandshakeInitiationMessage(hi.data)
}

func (hi *handshakeInitiation) Open() ([]byte, bool) {
	if len(hi.data) != header.HandshakeInitiationSize {
		hi.logV(3).Printf("Invalid handshake initiation size")
		return nil, false
	}
	if !hi.checkMAC1() {
		hi.logV(3).Print("Invalid mac1")
		return nil, false
	}
	if hi.conn.isUnderLoad() && !hi.checkMAC2() {
		hi.logV(3).Print("Invalid mac2, cookie reply")
		r, err := hi.cookieReply()
		if err != nil {
			hi.logV(1).Printf("Failed to gernate cookie reply: %v", err)
			return nil, false
		}
		return r, true
	}
	peerSender := hi.msg().Sender()
	h, ck := initialHash, initialChainKey
	hh := newHandshakeHelper(&h, &ck)
	result, err := hh.ParseHandshakeInitiation(hi.msg(), hi.conn.staticPriv, hi.conn.staticPub)
	if err != nil {
		hi.logV(3).Printf("Invalid handshake initiation: %v", err)
		return nil, false
	}
	p, ok := hi.conn.peer(result.peerStaticPub)
	if !ok {
		hi.logV(3).Printf("Peer not found: %v", result.peerStaticPub)
		return nil, false
	}
	if p.blocked.AtomicRead() {
		hi.logV(3).Print("Peer is blocked")
		return nil, false
	}
	if !p.handshakeTimestampFilter.Filter(&result.time) {
		hi.logV(3).Print("A newer initiation is received")
		return nil, false
	}
	var esk, epk Key
	if err := utils.DHGenerate(&esk, &epk); err != nil {
		hi.logV(1).Printf("DHGenerate error: %v", err)
		return nil, false
	}
	resp := header.HandshakeResponseMessage(hi.buf.BytesN(header.HandshakeResponseSize))
	err = hh.SetEmpty(
		resp,
		hi.conn.staticPriv,
		hi.conn.staticPub,
		&esk,
		&epk,
		&result.peerStaticPub,
		hi.msg().Ephemeral(),
		p.psk.AtomicRead(),
	)
	if err != nil {
		hi.logV(1).Printf("Failed to genreate response message: %v", err)
		return nil, false
	}
	rk, sk := hh.KDF2(nil)
	rc, err := chacha20poly1305.New(rk[:])
	if err != nil {
		hi.logV(1).Printf("New chacha20poly1305 error: %v, key=%0x", err, rk)
		return nil, false
	}
	sc, err := chacha20poly1305.New(sk[:])
	if err != nil {
		hi.logV(1).Printf("New chacha20poly1305 error: %v, key=%0x", err, sk)
		return nil, false
	}

	s := secureSession{
		peer:          p,
		receiver:      peerSender,
		hash:          hh.hash,
		sendCipher:    sc,
		recvCipher:    rc,
		establishTime: hi.time,

		// isInitiator: false,
		// sendCount: 0,
	}
	if err := hi.conn.saveSession(&s); err != nil {
		hi.logV(1).Printf("Failed to save session: %v", err)
		return nil, false
	}
	hi.session = &s

	header.SetType(resp, header.Response)
	resp.SetSender(s.sender)
	resp.SetReceiver(s.receiver)
	resp.SetEphemeral(epk[:])

	p.RLock()
	mac1, _ := p.setMACs(resp)
	p.RUnlock()

	s.Lock()
	s.mac1 = *mac1
	s.Unlock()

	return resp, true
}
