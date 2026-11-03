package benchmark_test

import (
	"encoding/json"
	"testing"

	wireguard "github.com/idy/wgc"
)

var decodedKey wireguard.Key

func BenchmarkKeyDecoding(b *testing.B) {
	var key wireguard.Key
	for i := range key {
		key[i] = byte(i + 1)
	}
	b.Run("base64", func(b *testing.B) {
		encoded := key.String()
		b.ReportAllocs()
		for b.Loop() {
			value, err := wireguard.KeyFromBase64(encoded)
			if err != nil {
				b.Fatal(err)
			}
			decodedKey = value
		}
	})
	b.Run("hex", func(b *testing.B) {
		encoded := key.HexString()
		b.ReportAllocs()
		for b.Loop() {
			value, err := wireguard.KeyFromHex(encoded)
			if err != nil {
				b.Fatal(err)
			}
			decodedKey = value
		}
	})
	b.Run("json", func(b *testing.B) {
		encoded, err := json.Marshal(key)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			if err := json.Unmarshal(encoded, &decodedKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGenerateKeys(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		var private, public wireguard.Key
		if err := wireguard.GenerateKeys(&private, &public); err != nil {
			b.Fatal(err)
		}
		decodedKey = public
	}
}
