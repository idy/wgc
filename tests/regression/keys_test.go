package regression_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	wireguard "github.com/idy/wgc"
)

func TestKeyFromBase64RejectsInvalidLengths(t *testing.T) {
	for _, size := range []int{0, wireguard.KeySize - 1, wireguard.KeySize + 1} {
		encoded := base64.StdEncoding.EncodeToString(make([]byte, size))
		if _, err := wireguard.KeyFromBase64(encoded); err == nil {
			t.Errorf("wireguard.KeyFromBase64 accepted %d decoded bytes", size)
		}
	}
}

func TestKeyFromBase64AcceptsKeySize(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(make([]byte, wireguard.KeySize))
	if _, err := wireguard.KeyFromBase64(encoded); err != nil {
		t.Fatalf("wireguard.KeyFromBase64 returned %v", err)
	}
}

func TestKeyFromBase64AcceptsLineBreaks(t *testing.T) {
	var want wireguard.Key
	for i := range want {
		want[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(want[:])
	input := encoded[:8] + "\r\n" + encoded[8:24] + "\n" + encoded[24:] + "\r\n"
	got, err := wireguard.KeyFromBase64(input)
	if err != nil || got != want {
		t.Fatalf("wireguard.KeyFromBase64 with line breaks = %x, %v; want %x", got, err, want)
	}
}

func TestKeyFromHexRejectsInvalidLengths(t *testing.T) {
	for _, size := range []int{0, 1, wireguard.KeySize - 1, wireguard.KeySize + 1, 2 * wireguard.KeySize} {
		encoded := strings.Repeat("ab", size)
		key, err := wireguard.KeyFromHex(encoded)
		if err == nil {
			t.Errorf("wireguard.KeyFromHex accepted %d decoded bytes", size)
		}
		if key != (wireguard.Key{}) {
			t.Errorf("wireguard.KeyFromHex returned a partial key for %d decoded bytes", size)
		}
	}
}

func TestKeyFromHexRoundTrip(t *testing.T) {
	var want wireguard.Key
	for i := range want {
		want[i] = byte(i + 0x80)
	}
	encoded := hex.EncodeToString(want[:])
	for _, input := range []string{encoded, strings.ToUpper(encoded)} {
		got, err := wireguard.KeyFromHex(input)
		if err != nil || got != want {
			t.Fatalf("wireguard.KeyFromHex round trip = %x, %v; want %x", got, err, want)
		}
	}
}

func TestKeyUnmarshalRejectsInvalidLengths(t *testing.T) {
	for _, size := range []int{0, wireguard.KeySize - 1, wireguard.KeySize + 1, 2 * wireguard.KeySize} {
		encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
		for _, format := range []string{"json", "text"} {
			t.Run(format+"/"+strconv.Itoa(size), func(t *testing.T) {
				defer func() {
					if value := recover(); value != nil {
						t.Errorf("invalid key caused a panic: %v", value)
					}
				}()
				original := wireguard.Key{7}
				key := original
				var err error
				if format == "json" {
					data, marshalErr := json.Marshal(encoded)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					err = json.Unmarshal(data, &key)
				} else {
					err = key.UnmarshalText([]byte(encoded))
				}
				if err == nil {
					t.Errorf("accepted %d decoded bytes", size)
				}
				if key != original {
					t.Error("invalid input changed the key")
				}
			})
		}
	}
}

func TestKeyUnmarshalRoundTrip(t *testing.T) {
	var original wireguard.Key
	for i := range original {
		original[i] = byte(i + 1)
	}
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var decoded wireguard.Key
			if format == "json" {
				encoded, err := json.Marshal(original)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
			} else if err := decoded.UnmarshalText([]byte(original.String())); err != nil {
				t.Fatal(err)
			}
			if decoded != original {
				t.Fatal("key changed during round trip")
			}
		})
	}
}
