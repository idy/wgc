package wireguard

import (
	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/tai64"
	"github.com/idy/wgc/internal/utils"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type handshakeHelper struct {
	hash           *[blake2s.Size]byte
	t0, t1, t2, t3 *Key
}

func newHandshakeHelper(hash *[blake2s.Size]byte, chainKey *Key) *handshakeHelper {
	return &handshakeHelper{
		hash: hash,
		t0:   new(Key),
		t1:   chainKey,
		t2:   new(Key),
		t3:   new(Key),
	}
}

type parseInitiationMessageResult struct {
	peerStaticPub Key
	time          tai64.NanoTime
}

func (h *handshakeHelper) KDF1(input []byte) []byte {
	utils.KDF(h.t0, h.t1, input, h.t1)
	return h.t1[:]
}

func (h *handshakeHelper) KDF2(input []byte) (_, _ []byte) {
	utils.KDF(h.t0, h.t1, input, h.t1, h.t2)
	return h.t1[:], h.t2[:]
}

func (h *handshakeHelper) KDF3(input []byte) (_, _, _ []byte) {
	utils.KDF(h.t0, h.t1, input, h.t1, h.t2, h.t3)
	return h.t1[:], h.t2[:], h.t3[:]
}

func (h *handshakeHelper) Hash(input ...[]byte) {
	utils.Hash(h.hash, h.hash[:], input...)
}

func (h *handshakeHelper) AEADOpen(key, dst, cipherText []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	_, err = aead.Open(dst, zeroBytes[:aead.NonceSize()], cipherText, h.hash[:])
	return err
}

func (h *handshakeHelper) AEADSeal(key, dst, plainText []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(dst, zeroBytes[:aead.NonceSize()], plainText, h.hash[:]), nil
}

func (h *handshakeHelper) SetStaticAndTimestamp(
	msg header.HandshakeInitiationMessage,
	timestamp tai64.NanoTime,
	staticPriv *Key,
	staticPub *Key,
	ephemeralPriv *Key,
	ephemeralPub *Key,
	peerStaticPub *Key,
) error {
	h.Hash(peerStaticPub[:])
	h.KDF1(ephemeralPub[:])
	h.Hash(ephemeralPub[:])
	dh, err := utils.DH(ephemeralPriv, peerStaticPub)
	if err != nil {
		return err
	}
	_, k := h.KDF2(dh[:])
	b, err := h.AEADSeal(k, msg.Static()[:0], staticPub[:])
	if err != nil {
		return err
	}
	h.Hash(b)
	dh, err = utils.DH(staticPriv, peerStaticPub)
	if err != nil {
		return err
	}
	_, k = h.KDF2(dh[:])
	if _, err := h.AEADSeal(k, msg.Timestamp()[:0], timestamp[:]); err != nil {
		return err
	}
	h.Hash(msg.Timestamp()[:])
	return nil
}

func (h *handshakeHelper) ParseHandshakeInitiation(
	msg header.HandshakeInitiationMessage,
	staticPriv *Key,
	staticPub *Key,
) (
	*parseInitiationMessageResult,
	error,
) {
	var result parseInitiationMessageResult
	h.Hash(staticPub[:])
	h.KDF1(msg.Ephemeral()[:])
	h.Hash(msg.Ephemeral()[:])
	dh, err := utils.DH(staticPriv, msg.Ephemeral())
	if err != nil {
		return nil, err
	}
	_, k := h.KDF2(dh[:])
	if err := h.AEADOpen(k, result.peerStaticPub[:0], msg.Static()[:]); err != nil {
		return nil, err
	}
	h.Hash(msg.Static()[:])
	dh, err = utils.DH(staticPriv, &result.peerStaticPub)
	if err != nil {
		return nil, err
	}
	_, k = h.KDF2(dh[:])
	if err := h.AEADOpen(k, result.time[:0], msg.Timestamp()[:]); err != nil {
		return nil, err
	}
	h.Hash(msg.Timestamp()[:])
	return &result, nil
}

func (h *handshakeHelper) SetEmpty(
	msg header.HandshakeResponseMessage,
	staticPriv *Key,
	staticPub *Key,
	ephemeralPriv *Key,
	ephemeralPub *Key,
	peerStaticPub *Key,
	peerEphemeralPub *Key,
	presharedKey *Key,
) error {
	h.KDF1(ephemeralPub[:])
	h.Hash(ephemeralPub[:])
	dh, err := utils.DH(ephemeralPriv, peerEphemeralPub)
	if err != nil {
		return err
	}
	h.KDF1(dh[:])
	dh, err = utils.DH(ephemeralPriv, peerStaticPub)
	if err != nil {
		return err
	}
	h.KDF1(dh[:])
	psk := zeroBytes[:KeySize]
	if presharedKey != nil {
		psk = presharedKey[:]
	}
	_, t, k := h.KDF3(psk)
	h.Hash(t)
	if _, err := h.AEADSeal(k, msg.Empty()[:0], []byte{}); err != nil {
		return err
	}
	h.Hash(msg.Empty()[:])
	return nil
}

func (h *handshakeHelper) ParseHandshakeResponse(
	msg header.HandshakeResponseMessage,
	ephemeralPriv *Key,
	staticPriv *Key,
	preshared *Key,
) error {
	h.KDF1(msg.Ephemeral()[:])
	h.Hash(msg.Ephemeral()[:])
	dh, err := utils.DH(ephemeralPriv, msg.Ephemeral())
	if err != nil {
		return err
	}
	h.KDF1(dh[:])
	dh, err = utils.DH(staticPriv, msg.Ephemeral())
	if err != nil {
		return err
	}
	h.KDF1(dh[:])
	psk := zeroBytes[:KeySize]
	if preshared != nil {
		psk = preshared[:]
	}
	_, t, k := h.KDF3(psk)
	h.Hash(t)
	if err := h.AEADOpen(k, nil, msg.Empty()[:]); err != nil {
		return err
	}
	h.Hash(msg.Empty()[:])
	return nil
}
