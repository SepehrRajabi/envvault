package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Envelope versions. Version 1 vaults carry an unkeyed SHA-256 of the
// plaintext in the header (still readable, never written). Version 2 vaults
// prefix the plaintext with a random per-vault MAC key *inside* the encrypted
// payload and store HMAC-SHA256(macKey, header fields || plaintext) in the
// header, so the header reveals nothing an attacker can use to confirm a
// plaintext guess offline, and tampering with the algorithm, recipients or
// commit metadata is detected after decryption.
const (
	legacyVersion  = 1
	currentVersion = 2

	macKeyLen = 32
)

// lpAppend appends a length-prefixed field so concatenated fields are
// unambiguous.
func lpAppend(dst, field []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len(field)))
	return append(dst, field...)
}

// headerMAC computes the v2 header checksum. The Checksum field itself is
// excluded.
func headerMAC(macKey []byte, hdr *envelopeHeader, plaintext []byte) (string, error) {
	var params, commit []byte
	var err error
	if len(hdr.ProviderParams) > 0 {
		if params, err = json.Marshal(hdr.ProviderParams); err != nil {
			return "", err
		}
	}
	if hdr.Commit != nil {
		if commit, err = json.Marshal(hdr.Commit); err != nil {
			return "", err
		}
	}

	msg := []byte("envvault/header-mac/v2\x00")
	msg = append(msg, hdr.Version)
	msg = lpAppend(msg, []byte(hdr.Algorithm))
	msg = lpAppend(msg, params)
	msg = lpAppend(msg, commit)
	msg = lpAppend(msg, plaintext)

	mac := hmac.New(sha256.New, macKey)
	mac.Write(msg)
	sum := mac.Sum(nil)
	SecureWipe(msg)
	return hex.EncodeToString(sum), nil
}

// sealInner returns macKey||plaintext (the bytes handed to the provider) and
// the macKey. The caller must wipe the returned inner buffer.
func sealInner(plaintext []byte) (inner, macKey []byte, err error) {
	inner = make([]byte, macKeyLen, macKeyLen+len(plaintext))
	if _, err = io.ReadFull(rand.Reader, inner); err != nil {
		return nil, nil, err
	}
	macKey = append([]byte(nil), inner...)
	inner = append(inner, plaintext...)
	return inner, macKey, nil
}

var errIntegrity = fmt.Errorf("checksum mismatch: data corrupted or wrong password")

// openInner verifies the integrity tag against what the provider returned
// and yields the plaintext (a sub-slice of raw). The caller must wipe raw.
func openInner(hdr *envelopeHeader, raw []byte) ([]byte, error) {
	switch hdr.Version {
	case legacyVersion:
		if !checksumMatches(raw, hdr.Checksum) {
			return nil, errIntegrity
		}
		return raw, nil
	case currentVersion:
		if len(raw) < macKeyLen {
			return nil, errIntegrity
		}
		macKey, plaintext := raw[:macKeyLen], raw[macKeyLen:]
		want, err := hex.DecodeString(hdr.Checksum)
		if err != nil {
			return nil, errIntegrity
		}
		gotHex, err := headerMAC(macKey, hdr, plaintext)
		if err != nil {
			return nil, err
		}
		got, _ := hex.DecodeString(gotHex)
		if !hmac.Equal(got, want) {
			return nil, errIntegrity
		}
		return plaintext, nil
	default:
		return nil, fmt.Errorf("unsupported version: %d", hdr.Version)
	}
}

// decryptEnvelope parses data, decrypts it with the provider named in the
// header, and verifies integrity. plaintext aliases raw; the caller must
// SecureWipe(raw) when finished (also on success).
func decryptEnvelope(data, password []byte) (plaintext, raw []byte, hdr *envelopeHeader, err error) {
	hdr, payload, err := parseEnvelope(data)
	if err != nil {
		return nil, nil, nil, err
	}

	prov, err := GetProvider(hdr.Algorithm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("vault uses algorithm %q which is not available: %w",
			hdr.Algorithm, err)
	}

	raw, err = prov.Decrypt(payload, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt: %w", err)
	}

	plaintext, err = openInner(hdr, raw)
	if err != nil {
		SecureWipe(raw)
		return nil, nil, nil, err
	}
	return plaintext, raw, hdr, nil
}
