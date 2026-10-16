package crypto

import (
	"encoding/binary"
	"strings"
	"testing"
)

func craft(hdrLen uint32, hdr string, payload []byte) []byte {
	b := []byte{currentVersion}
	b = binary.BigEndian.AppendUint32(b, hdrLen)
	b = append(b, hdr...)
	return append(b, payload...)
}

// Crafted vaults must produce errors, never panics.
func TestMalformedEnvelopesDoNotPanic(t *testing.T) {
	good := `{"v":1,"alg":"aes256gcm-argon2id","chk":"` + strings.Repeat("ab", 32) + `"}`
	cases := map[string][]byte{
		"hdrLen wraps uint32": craft(0xfffffffc, "xxx", nil),
		"hdrLen max":          craft(0xffffffff, "xxx", nil),
		"hdrLen > data":       craft(100, "{}", nil),
		"short checksum":      craft(uint32(len(`{"v":1,"alg":"aes256gcm-argon2id","chk":"ab"}`)), `{"v":1,"alg":"aes256gcm-argon2id","chk":"ab"}`, make([]byte, 60)),
		"non-hex checksum":    craft(uint32(len(strings.Replace(good, "ab", "zz", -1))), strings.Replace(good, "ab", "zz", -1), make([]byte, 60)),
		"shamir no payload":   craft(uint32(len(good)), good, nil),
		"only version":        {currentVersion},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			if _, err := Verify(data); err == nil {
				t.Error("Verify: expected error")
			}
			_, _ = PeekAlgorithm(data)
			_, _ = Decrypt(data, []byte("x"), nil)
			_, _ = DecryptSecure(data, []byte("x"), nil)
			_, _ = DecryptWithMetadata(data, []byte("x"), nil)
			_, _ = DecodeShamirPayloadThreshold(data)
		})
	}
}
