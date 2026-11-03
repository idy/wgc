package wireguard

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/idy/wgc/internal/header"
	"github.com/idy/wgc/internal/utils"
)

const KeySize = header.KeySize

type Key = header.Key

var GenerateKeys = utils.DHGenerate
var MustGenerateKeys = utils.MustDHGenerate

func KeyFromHex(s string) (k Key, err error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("invalid key length: got %d bytes, want %d", len(b), KeySize)
	}
	copy(k[:], b)
	return
}

func KeyFromBase64(s string) (k Key, err error) {
	err = k.UnmarshalText([]byte(s))
	return
}

func MustKeyFromBase64(s string) (k Key) {
	k, err := KeyFromBase64(s)
	if err != nil {
		panic(err)
	}
	return
}

const (
	// The UTF-8 string literal “Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s”, 37
	// bytes of output.
	construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

	// The UTF-8 string literal “WireGuard v1 zx2c4 Jason@zx2c4.com”, 34 bytes
	// of output.
	identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"

	// The UTF-8 string literal “mac1----”, 8 bytes of output.
	mac1Label = "mac1----"

	// The UTF-8 string literal “cookie--”, 8 bytes of output.
	cookieLabel = "cookie--"
)

var (
	initialChainKey Key
	initialHash     [KeySize]byte
	zeroBytes       []byte
)

func init() {
	utils.Hash(initialChainKey.Ptr(), []byte(construction))
	utils.Hash(&initialHash, initialChainKey[:], []byte(identifier))
	zeroBytes = make([]byte, 65535)
}

const (
	// Preliminaries
	// The following constants are used for the timer state system
	rekeyAfterMessages  uint64 = 1 << 60
	rejectAfterMessages uint64 = (1 << 64) - (1 << 13) - 1

	rekeyTimeout     = 5 * time.Second
	rekeyAfterTime   = 2 * time.Minute
	rejectAfterTime  = 3 * time.Minute
	rekeyAttemptTime = 90 * time.Second
	keepaliveTimeout = 10 * time.Second

	cookieSecretRotationDuration = 2 * time.Minute
)
