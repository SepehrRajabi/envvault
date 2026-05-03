package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

const currentVersion = 1

type envelopeHeader struct {
	Version   uint8  `json:"v"`
	Algorithm string `json:"alg"`
	Checksum  string `json:"chk"` // SHA256 of plaintext, hex
	// ProviderParams is optional extra metadata from the provider
	ProviderParams map[string]any `json:"params,omitempty"`
	// Commit is optional git commit metadata captured at encryption time.
	Commit *GitCommitMetadata `json:"commit,omitempty"`
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

	// Get algorithm-specific payload
	payload, err := p.Encrypt(plaintext, password)
	if err != nil {
		return nil, fmt.Errorf("provider %s encrypt: %w", p.AlgorithmID(), err)
	}

	// Build envelope
	checksum := sha256.Sum256(plaintext)
	hdr := envelopeHeader{
		Version:   currentVersion,
		Algorithm: p.AlgorithmID(),
		Checksum:  fmt.Sprintf("%x", checksum[:]),
	}

	if md, ok := p.(ProviderMetadata); ok {
		hdr.ProviderParams = md.Metadata()
	}

	if commitMeta, err := GetGitCommitMetadata(); err == nil && commitMeta != nil {
		hdr.Commit = commitMeta
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
func Decrypt(data, password []byte, p Provider) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty input")
	}

	version := data[0]

	if version != currentVersion {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	if len(data) < 5 {
		return nil, fmt.Errorf("corrupted data: incomplete header")
	}

	hdrLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < int(5+hdrLen) {
		return nil, fmt.Errorf("corrupted data: header truncated")
	}

	var hdr envelopeHeader
	if err := json.Unmarshal(data[5:5+hdrLen], &hdr); err != nil {
		return nil, fmt.Errorf("parsing envelope: %w", err)
	}

	// Lookup provider
	p, err := GetProvider(hdr.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("vault uses algorithm %q which is not available: %w",
			hdr.Algorithm, err)
	}

	payload := data[5+hdrLen:]
	plaintext, err := p.Decrypt(payload, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// Verify integrity
	checksum := sha256.Sum256(plaintext)
	if fmt.Sprintf("%x", checksum[:]) != hdr.Checksum {
		return nil, fmt.Errorf("checksum mismatch: data corrupted or wrong password")
	}

	return plaintext, nil
}

// PeekAlgorithm reads just the envelope header to determine what algorithm was used.
// This is useful for deciding whether to prompt for a password before decryption.
func PeekAlgorithm(data []byte) (string, error) {
	if len(data) < 1 {
		return "", fmt.Errorf("empty input")
	}

	if data[0] != currentVersion {
		return "", fmt.Errorf("unsupported vault version: %d", data[0])
	}

	if len(data) < 5 {
		return "", fmt.Errorf("corrupted data: incomplete header")
	}

	hdrLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < int(5+hdrLen) {
		return "", fmt.Errorf("corrupted data: header truncated")
	}

	var hdr envelopeHeader
	if err := json.Unmarshal(data[5:5+hdrLen], &hdr); err != nil {
		return "", fmt.Errorf("parsing envelope: %w", err)
	}

	return hdr.Algorithm, nil
}

// Verify checks the structural integrity of a vault file without requiring a password.
// It validates the version, header, algorithm, and payload existence.
func Verify(data []byte) (*envelopeHeader, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty input")
	}

	if data[0] != currentVersion {
		return nil, fmt.Errorf("unsupported vault version: %d", data[0])
	}

	if len(data) < 5 {
		return nil, fmt.Errorf("corrupted data: incomplete header length")
	}

	hdrLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < int(5+hdrLen) {
		return nil, fmt.Errorf("corrupted data: header truncated")
	}

	var hdr envelopeHeader
	if err := json.Unmarshal(data[5:5+hdrLen], &hdr); err != nil {
		return nil, fmt.Errorf("corrupted data: invalid header JSON: %w", err)
	}

	if hdr.Algorithm == "" {
		return nil, fmt.Errorf("corrupted data: missing algorithm in header")
	}

	if hdr.Checksum == "" {
		return nil, fmt.Errorf("corrupted data: missing checksum in header")
	}

	// Verify payload actually exists
	if len(data) <= int(5+hdrLen) {
		return nil, fmt.Errorf("corrupted data: missing payload")
	}

	// Verify the algorithm is one we actually support
	if _, err := GetProvider(hdr.Algorithm); err != nil {
		return nil, fmt.Errorf("vault uses unknown algorithm %q (provider not registered)", hdr.Algorithm)
	}

	return &hdr, nil
}
