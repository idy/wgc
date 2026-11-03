package wireguard

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/idy/wgc/internal/header"
	cryptoutils "github.com/idy/wgc/internal/utils"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestExpiredTransportDataCannotMutateSession(t *testing.T) {
	conn, packet := transportReceiver(t)
	session, _ := conn.session(7)
	session.establishTime = time.Now().Add(-rejectAfterTime - time.Second)
	if _, accepted := packet(0).Open(); accepted {
		t.Fatal("expired session accepted a transport packet")
	}
	if !session.Snapshot().lastRecvTime.IsZero() {
		t.Fatal("expired packet refreshed receive activity")
	}
	// A rejected packet must not consume its counter in the replay window.
	session.establishTime = time.Now()
	if _, accepted := packet(0).Open(); !accepted {
		t.Fatal("expired packet consumed a valid counter")
	}
}

func TestAuthenticatedEmptyTransportDataIsDeliverable(t *testing.T) {
	conn, _ := transportReceiver(t)
	session, _ := conn.session(7)
	message := make(header.TransportDataMessage, header.EmptyTransportDataSize)
	header.SetType(message, header.TransportData)
	message.SetCounter(0)
	session.Snapshot().recvCipher.Seal(message.Packet()[:0], message.Nonce()[:], nil, nil)
	message.SetReceiver(7)
	packet := &transportData{conn: conn, time: time.Now(), data: message, typ: header.TransportData}
	data, accepted := packet.Open()
	if !accepted || data == nil || len(data) != 0 {
		t.Fatalf("empty transport payload = %v, accepted = %v; want non-nil empty data", data, accepted)
	}
}

func TestStaleHandshakeResponseCannotChangePeerState(t *testing.T) {
	fixture := newHandshakeResponseFixture(t)
	msg := &handshakeResponse{conn: fixture.initiator, time: time.Now(), data: bytes.Clone(fixture.response), typ: header.Response}
	if _, accepted := msg.Open(); !accepted {
		t.Fatal("valid response rejected")
	}
	fixture.peer.discardHandshake(fixture.session)
	fixture.initiator.stats.RLock()
	accepted := fixture.initiator.updateStateAfterRecv((*inboundMessage)(msg), nil)
	fixture.initiator.stats.RUnlock()
	if accepted {
		t.Fatal("stale response was attached to peer state")
	}
	fixture.peer.RLock()
	current := fixture.peer.current
	fixture.peer.RUnlock()
	if current != nil {
		t.Fatal("stale response installed a current session")
	}
}

func TestHandshakeConfirmsPassiveResponderWithoutApplicationWrite(t *testing.T) {
	fixture := newHandshakeResponseFixture(t)
	responderSession, ok := fixture.responder.session(header.HandshakeResponseMessage(fixture.response).Sender())
	if !ok {
		t.Fatal("responder session not registered")
	}
	responderPeer := responderSession.peer
	responderPeer.Lock()
	responderPeer.next = responderSession
	responderPeer.Unlock()
	response := &inboundMessage{conn: fixture.initiator, time: time.Now(), data: bytes.Clone(fixture.response)}
	if _, err := fixture.initiator.handleInboundMessage(response); err != nil {
		t.Fatal(err)
	}
	tr := fixture.initiator.transport.(*channelTransport)
	select {
	case packet := <-tr.outgoing:
		if header.Type(packet.data) != header.TransportData || len(packet.data) != header.EmptyTransportDataSize {
			t.Fatal("response did not trigger an empty transport confirmation")
		}
		confirmation := &inboundMessage{conn: fixture.responder, time: time.Now(), data: packet.data, addr: packet.addr}
		if data, err := fixture.responder.handleInboundMessage(confirmation); err != nil || data == nil || len(data) != 0 {
			t.Fatalf("confirmation payload = %v, error = %v", data, err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake response did not send a confirmation")
	}
	responderPeer.RLock()
	confirmed := responderPeer.current == responderSession && responderPeer.next == nil
	responderPeer.RUnlock()
	if !confirmed {
		t.Fatal("passive responder did not promote its session")
	}
}

func TestCookieReplyCannotRoamPeer(t *testing.T) {
	conn := boundedConn(t)
	key := testKey(t)
	p, ok := conn.peer(key)
	if !ok {
		t.Fatal("peer not admitted")
	}
	original := netip.MustParseAddrPort("127.0.0.1:51820")
	other := netip.MustParseAddrPort("127.0.0.2:51821")
	p.Update(&PeerConfig{Addr: original, DisableHandshakeInitiation: true})
	session := &secureSession{peer: p, isInitiator: true, mac1: [header.CookieSize]byte{1}}
	if err := conn.saveSession(session); err != nil {
		t.Fatal(err)
	}
	// A cookie-reply key and its associated data are visible to an observer.
	var cookieKey Key
	cryptoutils.Hash(cookieKey.Ptr(), []byte(cookieLabel), key[:])
	cipher, err := chacha20poly1305.NewX(cookieKey[:])
	if err != nil {
		t.Fatal(err)
	}
	message := make(header.CookieReplyMessage, header.CookieReplySize)
	header.SetType(message, header.CookieReply)
	binary.LittleEndian.PutUint32(message[4:8], session.sender)
	cookie := bytes.Repeat([]byte{3}, header.CookieSize)
	cipher.Seal(message.Cookie()[:0], message.Nonce()[:], cookie, session.mac1[:])
	msg := &inboundMessage{conn: conn, time: time.Now(), data: message, addr: other}
	if _, err := conn.handleInboundMessage(msg); err != nil {
		t.Fatal(err)
	}
	if addr := p.RemoteAddr(); addr != original {
		t.Fatalf("cookie reply changed endpoint to %v; want %v", addr, original)
	}
	p.RLock()
	gotCookie := p.cookie
	p.RUnlock()
	if !bytes.Equal(gotCookie[:], cookie) {
		t.Fatal("valid cookie reply was not saved")
	}
}
