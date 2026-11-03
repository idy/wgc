package header

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/idy/wgc/internal/tai64"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type MessageType uint32

func (t MessageType) String() string {
	switch t {
	default:
		return fmt.Sprintf("%d", t)
	case Initiation:
		return "HandshakeInitiationMessage"
	case Response:
		return "HandshakeResponseMessage"
	case CookieReply:
		return "CookieReplyMessage"
	case TransportData:
		return "TransportDataMessage"
	}
}

const (
	_ = MessageType(iota)
	Initiation
	Response
	CookieReply
	TransportData
)

const (
	HandshakeInitiationSize = 148                                                 // size of handshake initiation message
	HandshakeResponseSize   = 92                                                  // size of response message
	CookieReplySize         = 64                                                  // size of cookie reply message
	TransportDataHeaderSize = 16                                                  // size of data preceding content in transport message
	EmptyTransportDataSize  = TransportDataHeaderSize + chacha20poly1305.Overhead // size of empty transport
)

const (
	CookieSize = blake2s.Size128
	KeySize    = chacha20poly1305.KeySize

	counterSize    = 8
	aeadTagSize    = chacha20poly1305.Overhead
	aeadCookieSize = CookieSize + aeadTagSize
	aeadKeySize    = KeySize + aeadTagSize
	aeadTAISize    = tai64.NanoSize + aeadTagSize
)

func Type(b []byte) (_ MessageType) {
	if len(b) < 4 {
		return
	}
	return MessageType(binary.LittleEndian.Uint32(b))
}

func SetType(b []byte, typ MessageType) {
	binary.LittleEndian.PutUint32(b[:4], uint32(typ))
}

type Key [KeySize]byte

func (k Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

func (k *Key) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n := base64.StdEncoding.DecodedLen(len(s))
	if n < KeySize {
		return errors.New("short key")
	} else if n > KeySize+1 {
		return errors.New("key is too long")
	}
	t, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("decode key: %v: %w", s, err)
	}
	*k = *(*Key)(t)
	return nil
}

func (k Key) MarshalText() ([]byte, error) {
	return ([]byte)(k.String()), nil
}

func (k *Key) UnmarshalText(text []byte) error {
	n := base64.StdEncoding.DecodedLen(len(text))
	if n < KeySize {
		return errors.New("short key")
	} else if n > KeySize+1 {
		return errors.New("key is too long")
	}
	var t Key
	_, err := base64.StdEncoding.Decode(t[:], text)
	if err != nil {
		return err
	}
	*k = t
	return nil
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) HexString() string {
	return hex.EncodeToString(k[:])
}

func (k *Key) Ptr() *[KeySize]byte {
	return (*[KeySize]byte)(k)
}

var zeroKey Key

func (k Key) IsZero() bool {
	return zeroKey == k
}

func (k Key) Cmp(another Key) int {
	return bytes.Compare(k[:], another[:])
}

func MAC1(b []byte) (prior []byte, mac *[CookieSize]byte) {
	s := len(b) - 2*CookieSize
	return b[:s], (*[CookieSize]byte)(b[s:])
}

func MAC2(b []byte) (prior []byte, mac *[CookieSize]byte) {
	s := len(b) - CookieSize
	return b[:s], (*[CookieSize]byte)(b[s:])
}
