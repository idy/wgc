package wireguard

import (
	"net/netip"
	"time"

	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/tai64"
	"github.com/idy/wgc/internal/utils"
)

type peerWriter struct {
	peer  *peer
	data  []byte
	start time.Time
	time  time.Time
}

func (w *peerWriter) isKeepalive() bool {
	return len(w.data) == 0
}

func (w *peerWriter) seal(dst []byte) ([]byte, netip.AddrPort, error) {
	blocked, curSession, addr := w.peer.conn.updateStateBeforeDataSent(w)

	if blocked {
		w.logV(2).Print("Peer blocked")
		return nil, netip.AddrPort{}, &ioError{
			Op:   "write",
			Err:  ErrPeerBlocked,
			Peer: w.peer.staticPub,
		}
	}
	if curSession == nil {
		w.logV(3).Print("No session")
		return nil, netip.AddrPort{}, &ioError{
			Op:          "write",
			Err:         ErrPeerNoSession,
			Peer:        w.peer.staticPub,
			IsTemporary: true,
		}
	}
	w.time = time.Now()
	ss := curSession.TxSnapshot(w.time)
	if w.time.Sub(ss.establishTime) > rejectAfterTime || ss.sendCount > rejectAfterMessages {
		w.logV(3).Print("Session outdated")
		return nil, netip.AddrPort{}, &ioError{
			Op:          "write",
			Err:         ErrPeerNoSession,
			Peer:        w.peer.staticPub,
			IsTemporary: true,
		}
	}

	m := header.TransportDataMessage(dst)
	header.SetType(m, header.TransportData)
	m.SetReceiver(0)
	m.SetCounter(ss.sendCount)
	b := ss.sendCipher.Seal(m.Packet()[:0], m.Nonce()[:], w.data, nil)
	m.SetReceiver(ss.receiver)
	return m[:header.TransportDataHeaderSize+len(b)], addr, nil
}

func (w *peerWriter) send(b []byte, addr netip.AddrPort) error {
	if _, err := w.peer.conn.transport.WriteTo(b, addr); err != nil {
		w.logV(2).Printf("Failed write: %v", err)
		return err
	}
	w.logV(3).Print("Sent")
	w.peer.conn.updateStateAfterDataSent(w)
	return nil
}

type initiationWriter struct {
	buf     []byte
	addr    netip.AddrPort
	session *secureSession
	start   time.Time
	time    time.Time
}

func (w *initiationWriter) Write() error {
	peer := w.session.peer

	h, ck := initialHash, initialChainKey
	hh := newHandshakeHelper(&h, &ck)
	msg := header.HandshakeInitiationMessage(w.buf[:header.HandshakeInitiationSize])
	var sk, pk Key
	if err := utils.DHGenerate(&sk, &pk); err != nil {
		w.logV(2).Printf("DHGenerate error: %v", err)
		return err
	}
	err := hh.SetStaticAndTimestamp(
		msg,
		tai64.FromTime(w.time),
		peer.conn.staticPriv,
		peer.conn.staticPub,
		&sk,
		&pk,
		peer.staticPub,
	)
	if err != nil {
		w.logV(2).Printf("Generate message error: %v", err)
		return err
	}
	header.SetType(msg, header.Initiation)
	msg.SetSender(w.session.sender)
	msg.SetEphemeral(pk[:])

	peer.RLock()
	mac1, _ := peer.setMACs(msg)
	addr := peer.addr
	peer.RUnlock()

	w.session.Lock()
	if w.session.state() == initiated {
		w.session.mac1 = *mac1
		w.session.hash = &h
		w.session.chainKey = &ck
		w.session.ephemeralPriv = &sk
		w.session.ephemeralPub = &pk
	}
	w.session.Unlock()
	if _, err := peer.conn.transport.WriteTo(msg, addr); err != nil {
		w.logV(2).Printf("Send error: %v", err)
		return err
	}
	w.logV(3).Print("Sent")
	peer.conn.updateStateAfterHandshakeInitiationSent(w)
	return nil
}
