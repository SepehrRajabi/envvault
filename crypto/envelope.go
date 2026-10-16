package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type envelopeHeader struct {
	Version   uint8  `json:"v"`
	Algorithm string `json:"alg"`
	Checksum  string `json:"chk"` // v2: HMAC-SHA256 tag, hex (v1: SHA-256 of plaintext)
	// ProviderParams is optional extra metadata from the provider
	ProviderParams map[string]any `json:"params,omitempty"`
	// Commit is optional git commit metadata captured at encryption time.
	Commit *GitCommitMetadata `json:"commit,omitempty"`
}

// checksumMatches reports whether plaintext's SHA-256 matches the hex-encoded
// checksum from an envelope header, using a constant-time comparison. This
// checksum is the sole tamper-detection mechanism for unauthenticated
// providers (e.g. plain ChaCha20 without Poly1305), so it's compared in
// constant time rather than with a short-circuiting == on the hex strings.
func checksumMatches(plaintext []byte, hexChecksum string) bool {
	want, err := hex.DecodeString(hexChecksum)
	if err != nil {
		return false
	}
	got := sha256.Sum256(plaintext)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

// splitEnvelope returns the raw header bytes and provider payload of a vault
// without parsing the header. hdrLen comes from the (untrusted) file, so the
// bounds check is done in uint64 to avoid uint32 wraparound.
func splitEnvelope(data []byte) (hdrJSON, payload []byte, err error) {
	if len(data) < 1 {
		return nil, nil, fmt.Errorf("empty input")
	}
	if data[0] != legacyVersion && data[0] != currentVersion {
		return nil, nil, fmt.Errorf("unsupported version: %d", data[0])
	}
	if len(data) < 5 {
		return nil, nil, fmt.Errorf("corrupted data: incomplete header")
	}
	hdrLen := uint64(binary.BigEndian.Uint32(data[1:5]))
	if hdrLen > uint64(len(data)-5) {
		return nil, nil, fmt.Errorf("corrupted data: header truncated")
	}
	end := 5 + int(hdrLen)
	return data[5:end], data[end:], nil
}

// parseEnvelope splits a vault and decodes its header.
func parseEnvelope(data []byte) (*envelopeHeader, []byte, error) {
	hdrJSON, payload, err := splitEnvelope(data)
	if err != nil {
		return nil, nil, err
	}
	hdrVersion := data[0]
	var h envelopeHeader
	if err := json.Unmarshal(hdrJSON, &h); err != nil {
		return nil, nil, fmt.Errorf("parsing envelope: %w", err)
	}
	if h.Version != hdrVersion {
		return nil, nil, fmt.Errorf("corrupted data: header version %d does not match envelope version %d", h.Version, hdrVersion)
	}
	return &h, payload, nil
}

// Encrypt uses the specified provider (or default) to encrypt data.
func Encrypt(plaintext, password []byte, provider ...Provider) ([]byte, error) {
	var p Provider
	if len(provider) > 0 && provider[0] != nil {
		p = provider[0]
	} else {
		p = Default()
		if p == nil {
			return nil, fmt.Errorf("no default provider set")
		}
	}

	// The provider encrypts macKey||plaintext, so the MAC key is only ever
	// recoverable by someone who can decrypt the vault.
	inner, macKey, err := sealInner(plaintext)
	if err != nil {
		return nil, err
	}
	defer SecureWipe(inner)
	defer SecureWipe(macKey)

	payload, err := p.Encrypt(inner, password)
	if err != nil {
		return nil, fmt.Errorf("provider %s encrypt: %w", p.AlgorithmID(), err)
	}

	// Build envelope
	hdr := envelopeHeader{
		Version:   currentVersion,
		Algorithm: p.AlgorithmID(),
	}

	if md, ok := p.(ProviderMetadata); ok {
		hdr.ProviderParams = md.Metadata()
	}

	if commitMeta, err := GetGitCommitMetadata(); err == nil && commitMeta != nil {
		hdr.Commit = commitMeta
	}

	if hdr.Checksum, err = headerMAC(macKey, &hdr, plaintext); err != nil {
		return nil, err
	}

	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}

	// Format: [version:1] [hdrLen:4] [hdrJSON] [payload]
	buf := make([]byte, 0, 1+4+len(hdrJSON)+len(payload))
	buf = append(buf, currentVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(hdrJSON)))
	buf = append(buf, hdrJSON...)
	buf = append(buf, payload...)

	return buf, nil
}

// Decrypt auto-detects algorithm from envelope and routes to correct provider.
//
// Deprecated: Use DecryptSecure instead. This function returns plaintext in unprotected
// memory, making it vulnerable to swapping to disk. DecryptSecure returns plaintext locked
// in RAM, preventing OS swap attacks.
func Decrypt(data, password []byte, p Provider) ([]byte, error) {
	plaintext, raw, _, err := decryptEnvelope(data, password)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), plaintext...)
	SecureWipe(raw)
	return out, nil
}

// PeekAlgorithm reads just the envelope header to determine what algorithm was used.
// This is useful for deciding whether to prompt for a password before decryption.
func PeekAlgorithm(data []byte) (string, error) {
	hdr, _, err := parseEnvelope(data)
	if err != nil {
		return "", err
	}

	return hdr.Algorithm, nil
}

// Verify checks the structural integrity of a vault file without requiring a password.
// It validates the version, header, algorithm, and payload existence.
func Verify(data []byte) (*envelopeHeader, error) {
	hdr, payload, err := parseEnvelope(data)
	if err != nil {
		return nil, err
	}

	if hdr.Algorithm == "" {
		return nil, fmt.Errorf("corrupted data: missing algorithm in header")
	}

	if hdr.Checksum == "" {
		return nil, fmt.Errorf("corrupted data: missing checksum in header")
	}
	if raw, err := hex.DecodeString(hdr.Checksum); err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("corrupted data: malformed checksum in header")
	}

	// Verify payload actually exists
	if len(payload) == 0 {
		return nil, fmt.Errorf("corrupted data: missing payload")
	}

	// Verify the algorithm is one we actually support
	if _, err := GetProvider(hdr.Algorithm); err != nil {
		return nil, fmt.Errorf("vault uses unknown algorithm %q (provider not registered)", hdr.Algorithm)
	}

	return hdr, nil
}
