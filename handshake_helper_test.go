package wireguard

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/tai64"
	"github.com/idy/wgc/internal/utils"
)

func BenchmarkHandshake(b *testing.B) {
	b.Run("without psk", func(b *testing.B) {
		var tc handshakeTestCase
		if err := tc.Init(); err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			tc.Run(b)
		}
	})
	b.Run("with psk", func(b *testing.B) {
		var tc handshakeTestCase
		if err := tc.Init(); err != nil {
			b.Fatal(err)
		}
		if err := tc.RandomPSK(); err != nil {
			b.Fatal(err)
		}
		for i := 0; i < b.N; i++ {
			tc.Run(b)
		}
	})
}

func TestHandshakeHelper(t *testing.T) {
	var tc handshakeTestCase
	t.Run("without psk", func(t *testing.T) {
		if err := tc.Init(); err != nil {
			t.Error(err)
		}
		tc.Run(t)
	})
	t.Run("with psk", func(t *testing.T) {
		if err := tc.Init(); err != nil {
			t.Error(err)
		}
		if err := tc.RandomPSK(); err != nil {
			t.Error(err)
		}
		tc.Run(t)
	})
}

type handshakeTestCase struct {
	time time.Time

	is, rs uint32

	psk *Key

	issk, ispk, iesk, iepk Key
	rssk, rspk, resk, repk Key

	buf [header.HandshakeInitiationSize]byte
}

func (tc *handshakeTestCase) Init() error {
	tc.time = time.Now()
	tc.is = 1
	tc.rs = 2
	tc.psk = nil
	if err := utils.DHGenerate(&tc.issk, &tc.ispk); err != nil {
		return err
	}
	if err := utils.DHGenerate(&tc.iesk, &tc.iepk); err != nil {
		return err
	}
	if err := utils.DHGenerate(&tc.rssk, &tc.rspk); err != nil {
		return err
	}
	if err := utils.DHGenerate(&tc.resk, &tc.repk); err != nil {
		return err
	}
	return nil
}

func (tc *handshakeTestCase) RandomPSK() error {
	tc.psk = new(Key)
	_, err := rand.Read(tc.psk[:])
	return err
}

func (tc *handshakeTestCase) Run(t testing.TB) {
	h1, ck1 := initialHash, initialChainKey
	ih := newHandshakeHelper(&h1, &ck1)

	h2, ck2 := initialHash, initialChainKey
	rh := newHandshakeHelper(&h2, &ck2)

	hsi := header.HandshakeInitiationMessage(tc.buf[:header.HandshakeInitiationSize])
	header.SetType(hsi, header.Initiation)
	hsi.SetSender(tc.is)
	hsi.SetEphemeral(tc.iepk[:])
	err := ih.SetStaticAndTimestamp(
		hsi,
		tai64.FromTime(tc.time),
		&tc.issk,
		&tc.ispk,
		&tc.iesk,
		&tc.iepk,
		&tc.rspk,
	)
	if err != nil {
		t.Fatalf("Initiator set static and timestamp error: %v", err)
	}
	r, err := rh.ParseHandshakeInitiation(
		hsi,
		&tc.rssk,
		&tc.rspk,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !handshakeHelperIsEqual(ih, rh) {
		t.Fatal("States are not equal after handshake initiation")
	}
	if r.peerStaticPub != tc.ispk {
		t.Fatal("Responder receives incorrect static pub key")
	}
	if r.time != tai64.FromTime(tc.time) {
		t.Fatal("Responder receives incorrect timestamp")
	}

	copy(tc.buf[:], zeroBytes)
	hsr := header.HandshakeResponseMessage(tc.buf[:header.HandshakeResponseSize])
	header.SetType(hsr, header.Response)
	hsr.SetSender(tc.rs)
	hsr.SetReceiver(tc.is)
	hsr.SetEphemeral(tc.repk[:])
	err = rh.SetEmpty(
		hsr,
		&tc.rssk,
		&tc.rspk,
		&tc.resk,
		&tc.repk,
		&tc.ispk,
		&tc.iepk,
		tc.psk,
	)
	if err != nil {
		t.Fatalf("Responder set empty error: %v", err)
	}
	err = ih.ParseHandshakeResponse(
		hsr,
		&tc.iesk,
		&tc.issk,
		tc.psk,
	)
	if err != nil {
		t.Fatalf("Initiator failed to parse handshake response: %v", err)
	}
	if !handshakeHelperIsEqual(ih, rh) {
		t.Fatalf("States are not equal after handshake response")
	}
}

func handshakeHelperIsEqual(i, r *handshakeHelper) bool {
	return *i.hash == *r.hash &&
		*i.t0 == *r.t0 &&
		*i.t1 == *r.t1 &&
		*i.t2 == *r.t2 &&
		*i.t3 == *r.t3
}
