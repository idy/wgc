package wireguard

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/idy/wgc/internal/bufpool"
	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/tai64"
	"github.com/idy/wgc/internal/utils"
)

var inboundMessagePool = sync.Pool{
	New: func() interface{} {
		return new(inboundMessage)
	},
}

type inboundMessage struct {
	conn *Conn
	time time.Time

	cookieSecret   [32]byte
	initiationTime tai64.NanoTime

	buf  *bufpool.Buffer
	data []byte
	addr netip.AddrPort

	typ     header.MessageType
	session *secureSession
}

func (msg *inboundMessage) setZero() {
	msg.conn = nil
	msg.time = time.Time{}
	copy(msg.cookieSecret[:], zeroBytes)
	msg.initiationTime = tai64.NanoTime{}
	msg.buf = nil
	msg.data = nil
	msg.addr = netip.AddrPort{}
	msg.typ = 0
	msg.session = nil
}

func (msg *inboundMessage) checkMAC1() bool {
	prior, got := header.MAC1(msg.data)
	var want [header.CookieSize]byte
	utils.Mac(&want, msg.conn.mac1VerifyKey, prior)
	return bytes.Equal(want[:], got[:])
}

func (msg *inboundMessage) checkMAC2() bool {
	prior, got := header.MAC2(msg.data)
	if bytes.Equal(got[:], zeroBytes[:len(got)]) {
		return false
	}
	var buf [32]byte

	cookie := (*[16]byte)(unsafe.Pointer(&buf))
	addrBytes := addrToBytes(buf[:], msg.addr)
	utils.Mac(cookie, msg.cookieSecret[:], addrBytes)

	want := (*[16]byte)(unsafe.Pointer(&buf))
	utils.Mac(want, cookie[:], prior)

	return bytes.Equal(want[:], got[:])
}

func (msg *inboundMessage) cookieReply() ([]byte, error) {
	_, m := header.MAC1(msg.data)
	mac1 := *m
	reply := header.CookieReplyMessage(msg.buf.BytesN(header.CookieReplySize))
	_, err := rand.Read(reply.Nonce()[:])
	if err != nil {
		return nil, err
	}

	plainTextCookie := (*[16]byte)(unsafe.Pointer(reply.Cookie()))
	addrBytes := addrToBytes(reply.Cookie()[:], msg.addr)
	utils.Mac(plainTextCookie, msg.cookieSecret[:], addrBytes)
	msg.logV(3).Printf("CookeReply: cookie=%0x", *plainTextCookie)

	msg.conn.cookieSealCipher.Seal(
		reply.Cookie()[:0],
		reply.Nonce()[:],
		plainTextCookie[:],
		mac1[:],
	)
	header.SetType(reply, header.CookieReply)
	return reply, nil
}

func (msg *inboundMessage) Read() error {
	conn := msg.conn

	n, addr, err := conn.transport.ReadFrom(msg.buf.Bytes())
	if err != nil {
		return err
	}
	msg.time = time.Now()
	if time.Since(conn.csgTime) > cookieSecretRotationDuration {
		if conn.csgTime.IsZero() {
			conn.logV(3).Print("Init cookie secret")
		} else {
			conn.logV(3).Print("Rotate cookie secret")
		}
		if _, err := rand.Read(conn.cookieSecret[:]); err != nil {
			return err
		}
		conn.csgTime = msg.time
	}
	msg.cookieSecret = conn.cookieSecret
	msg.data = msg.buf.BytesN(n)
	msg.addr = addr
	msg.typ = 0
	msg.session = nil
	msg.initiationTime = tai64.NanoTime{}
	return nil
}

// Open opens the inbound message, returns the data in the message or some
// derived data, and a boolean value which indicates whether this message is a
// valid and authenticated message.
func (msg *inboundMessage) Open() (data []byte, valid bool) {
	defer func() {
		if valid {
			msg.logV(3).Printf("Recved OK(%d)", len(data))
		}
	}()
	if len(msg.data) < 4 {
		msg.logV(3).Print("Invalid wireguard message size")
		return nil, false
	}
	msg.typ = header.Type(msg.data)
	switch msg.typ {
	case header.Initiation:
		return (*handshakeInitiation)(msg).Open()
	case header.Response:
		return (*handshakeResponse)(msg).Open()
	case header.TransportData:
		return (*transportData)(msg).Open()
	case header.CookieReply:
		return (*cookieReply)(msg).Open()
	}
	msg.logV(3).Print("Invalid wireguard message type")
	return nil, false
}
