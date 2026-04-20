package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"
)

const shamirPayloadVersion = 1

// ShamirAESGCMProvider encrypts with AES-GCM and requires K-of-N Shamir shares
// to reconstruct the secret used for key derivation.
type ShamirAESGCMProvider struct {
	Time      uint32
	Memory    uint32
	Threads   uint8
	SaltLen   int
	NonceLen  int
	Shares    int
	Threshold int

	lastGeneratedShares []string
}

func init() {
	defaultShamir := &ShamirAESGCMProvider{
		Time:      3,
		Memory:    64 * 1024,
		Threads:   4,
		SaltLen:   32,
		NonceLen:  12,
		Shares:    5,
		Threshold: 3,
	}
	Register(defaultShamir)
}

func (s *ShamirAESGCMProvider) AlgorithmID() string {
	return "shamir-aes256gcm"
}

func (s *ShamirAESGCMProvider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          s.AlgorithmID(),
		Description: "aes256-gcm with k-of-n shamir secret shares",
		Secure:      true,
	}
}

func (s *ShamirAESGCMProvider) GeneratedShares() []string {
	return slices.Clone(s.lastGeneratedShares)
}

func (s *ShamirAESGCMProvider) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}
	if s.Threshold < 2 || s.Threshold > 255 {
		return nil, fmt.Errorf("invalid threshold %d (must be 2-255)", s.Threshold)
	}
	if s.Shares < s.Threshold || s.Shares > 255 {
		return nil, fmt.Errorf("invalid shares count %d (must be >= threshold and <=255)", s.Shares)
	}

	salt, nonce, ciphertext, err := encryptAESGCMArgon2(
		plaintext,
		password,
		s.Time,
		s.Memory,
		s.Threads,
		s.SaltLen,
		s.NonceLen,
	)
	if err != nil {
		return nil, err
	}

	encoded, err := SplitSecretToBase64(password, s.Shares, s.Threshold)
	if err != nil {
		return nil, err
	}
	s.lastGeneratedShares = encoded

	// Payload format:
	// [version:1][threshold:1][saltLen:1][nonceLen:1][salt][nonce][ciphertext]
	payload := make([]byte, 0, 4+len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, shamirPayloadVersion)
	payload = append(payload, byte(s.Threshold))
	payload = append(payload, byte(len(salt)))
	payload = append(payload, byte(len(nonce)))
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return payload, nil
}

func (s *ShamirAESGCMProvider) Decrypt(payload, password []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("payload too small")
	}
	if payload[0] != shamirPayloadVersion {
		return nil, fmt.Errorf("unsupported shamir payload version: %d", payload[0])
	}

	threshold := int(payload[1])
	saltLen := int(payload[2])
	nonceLen := int(payload[3])
	if threshold < 2 {
		return nil, fmt.Errorf("invalid threshold in payload")
	}

	headerLen := 4
	if len(payload) < headerLen+saltLen+nonceLen {
		return nil, fmt.Errorf("payload truncated")
	}
	salt := payload[headerLen : headerLen+saltLen]
	nonce := payload[headerLen+saltLen : headerLen+saltLen+nonceLen]
	ciphertext := payload[headerLen+saltLen+nonceLen:]
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("payload missing ciphertext")
	}

	shares, err := parseSharesInput(password)
	if err != nil {
		return nil, err
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("need at least %d shares, got %d", threshold, len(shares))
	}

	secret, err := combineShares(shares[:threshold])
	if err != nil {
		return nil, fmt.Errorf("reconstructing secret: %w", err)
	}
	defer SecureZero(secret)

	return decryptAESGCMArgon2(ciphertext, secret, salt, nonce, s.Time, s.Memory, s.Threads)
}

func parseSharesInput(input []byte) ([][]byte, error) {
	raw := strings.TrimSpace(string(input))
	if raw == "" {
		return nil, fmt.Errorf("no shares provided")
	}

	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return nil, fmt.Errorf("no shares provided")
	}

	return decodeBase64Shares(parts)
}

func decodeBase64Shares(parts []string) ([][]byte, error) {
	out := make([][]byte, 0, len(parts))
	for _, part := range parts {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid share encoding: %w", err)
		}
		out = append(out, decoded)
	}
	return out, nil
}

// SplitSecretToBase64 splits a secret into n shares where k are needed
// for reconstruction and returns each share base64-encoded.
func SplitSecretToBase64(secret []byte, n, k int) ([]string, error) {
	rawShares, err := splitSecret(secret, n, k)
	if err != nil {
		return nil, err
	}
	encoded := make([]string, 0, len(rawShares))
	for _, share := range rawShares {
		encoded = append(encoded, base64.StdEncoding.EncodeToString(share))
	}
	return encoded, nil
}

// CombineSecretFromBase64 reconstructs the secret from base64-encoded shares.
func CombineSecretFromBase64(encodedShares []string) ([]byte, error) {
	rawShares, err := decodeBase64Shares(encodedShares)
	if err != nil {
		return nil, err
	}
	return combineShares(rawShares)
}

func splitSecret(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 || n < k {
		return nil, fmt.Errorf("invalid shamir params n=%d k=%d", n, k)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	shares := make([][]byte, n)
	for i := range n {
		shares[i] = make([]byte, 1+len(secret))
		shares[i][0] = byte(i + 1) // x-coordinate
	}

	coeffs := make([]byte, k)
	for idx, sb := range secret {
		coeffs[0] = sb
		if _, err := io.ReadFull(rand.Reader, coeffs[1:]); err != nil {
			return nil, err
		}
		for i := range n {
			x := shares[i][0]
			shares[i][1+idx] = evalPoly(coeffs, x)
		}
	}

	return shares, nil
}

func combineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("need at least 2 shares")
	}

	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, fmt.Errorf("invalid share length")
	}

	xs := make(map[byte]struct{}, len(shares))
	for _, share := range shares {
		if len(share) != shareLen {
			return nil, fmt.Errorf("shares have inconsistent lengths")
		}
		x := share[0]
		if x == 0 {
			return nil, fmt.Errorf("invalid share x=0")
		}
		if _, exists := xs[x]; exists {
			return nil, fmt.Errorf("duplicate share x=%d", x)
		}
		xs[x] = struct{}{}
	}

	secret := make([]byte, shareLen-1)
	for b := 1; b < shareLen; b++ {
		var out byte
		for i := range len(shares) {
			xi := shares[i][0]
			yi := shares[i][b]
			li := byte(1)

			for j := range len(shares) {
				if i == j {
					continue
				}
				xj := shares[j][0]
				num := xj
				den := xi ^ xj // subtraction in GF(256) == XOR
				if den == 0 {
					return nil, fmt.Errorf("invalid duplicate x coordinates")
				}
				li = gfMul(li, gfDiv(num, den))
			}

			out ^= gfMul(yi, li)
		}
		secret[b-1] = out
	}

	return secret, nil
}

func evalPoly(coeffs []byte, x byte) byte {
	// Horner's method over GF(256).
	var out byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		out = gfMul(out, x) ^ coeffs[i]
		if i == 0 {
			break
		}
	}
	return out
}

func gfMul(a, b byte) byte {
	var res byte
	for b > 0 {
		if b&1 == 1 {
			res ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b // x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1
	}
	return res
}

func gfPow(a byte, n int) byte {
	var out byte = 1
	for range n {
		out = gfMul(out, a)
	}
	return out
}

func gfInv(a byte) byte {
	// In GF(2^8), a^254 == a^-1 for non-zero a.
	if a == 0 {
		return 0
	}
	return gfPow(a, 254)
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		return 0
	}
	return gfMul(a, gfInv(b))
}

// DecodeShamirPayloadThreshold reads the threshold from a shamir payload.
// Data is expected to be the full vault bytes with envelope.
func DecodeShamirPayloadThreshold(data []byte) (int, error) {
	if len(data) < 5 {
		return 0, fmt.Errorf("corrupted data: incomplete header")
	}
	hdrLen := binary.BigEndian.Uint32(data[1:5])
	if len(data) < int(5+hdrLen+2) {
		return 0, fmt.Errorf("corrupted data: missing shamir payload")
	}
	payload := data[5+hdrLen:]
	if payload[0] != shamirPayloadVersion {
		return 0, fmt.Errorf("unsupported shamir payload version: %d", payload[0])
	}
	return int(payload[1]), nil
}
