package crypto

import "errors"

var (
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidPayload  = errors.New("invalid payload, too short to contain salt and nonce")
)

type ChaCha20Provider struct{}

func (c *ChaCha20Provider) AlgorithmID() string {
	return "chacha20"
}

func initializeState(key, nonce []byte, blockCount uint32) [16]uint32 {
	var state [16]uint32

	// Initialize state with constants, key, nonce, and block counter
	copy(state[0:4], []uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}) // "expand 32-byte k"
	for i := range 8 {
		state[4+i] = uint32(key[i*4]) | (uint32(key[i*4+1]) << 8) | (uint32(key[i*4+2]) << 16) | (uint32(key[i*4+3]) << 24)
	}
	state[12] = blockCount
	for i := range 3 {
		state[13+i] = uint32(nonce[i*4]) | (uint32(nonce[i*4+1]) << 8) | (uint32(nonce[i*4+2]) << 16) | (uint32(nonce[i*4+3]) << 24)
	}

	return state
}

func quarterRound(a, b, c, d *uint32) {
	*a += *b
	*d ^= *a
	*d = (*d << 16) | (*d >> 16)

	*c += *d
	*b ^= *c
	*b = (*b << 12) | (*b >> 20)

	*a += *b
	*d ^= *a
	*d = (*d << 8) | (*d >> 24)

	*c += *d
	*b ^= *c
	*b = (*b << 7) | (*b >> 25)
}

func mixing(state *[16]uint32) {
	for range 10 {
		// Column rounds
		quarterRound(&state[0], &state[4], &state[8], &state[12])
		quarterRound(&state[1], &state[5], &state[9], &state[13])
		quarterRound(&state[2], &state[6], &state[10], &state[14])
		quarterRound(&state[3], &state[7], &state[11], &state[15])

		// Diagonal rounds
		quarterRound(&state[0], &state[5], &state[10], &state[15])
		quarterRound(&state[1], &state[6], &state[11], &state[12])
		quarterRound(&state[2], &state[7], &state[8], &state[13])
		quarterRound(&state[3], &state[4], &state[9], &state[14])
	}
}

func generateKeyStream(key, nonce []byte, blockCount uint32) []byte {
	initialState := initializeState(key, nonce, blockCount)
	workingState := initialState

	mixing(&workingState)

	// Add the original state to the working state
	for i := range 16 {
		workingState[i] += initialState[i]
	}

	keyStream := make([]byte, 64)
	for i := range 16 {
		keyStream[i*4] = byte(workingState[i] & 0xFF)
		keyStream[i*4+1] = byte((workingState[i] >> 8) & 0xFF)
		keyStream[i*4+2] = byte((workingState[i] >> 16) & 0xFF)
		keyStream[i*4+3] = byte((workingState[i] >> 24) & 0xFF)
	}

	return keyStream
}

func (c *ChaCha20Provider) Encrypt(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}

	nonce, err := RandomBytes(12)
	if err != nil {
		return nil, err
	}

	salt, err := RandomBytes(16)
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	ciphertext := make([]byte, len(plaintext))

	// Process plaintext in 64-byte blocks, incrementing the counter
	for i := 0; i < len(plaintext); i += 64 {
		end := min(i+64, len(plaintext))

		blockCount := uint32(i / 64)
		keyStream := generateKeyStream(key, nonce, blockCount)

		for j := i; j < end; j++ {
			ciphertext[j] = plaintext[j] ^ keyStream[j-i]
		}
	}

	// Prepend salt and nonce IN PLAINTEXT to the ciphertext
	// Format: [Salt (16)] [Nonce (12)] [Ciphertext (...)]
	output := make([]byte, 0, 16+12+len(ciphertext))
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return output, nil
}

func (c *ChaCha20Provider) Decrypt(payload, password []byte) ([]byte, error) {
	// 1. Validate payload length (must contain at least 16 bytes salt + 12 bytes nonce)
	if len(payload) < 28 {
		return nil, ErrInvalidPayload
	}

	// 2. Extract the salt, nonce, and ciphertext
	salt := payload[:16]
	nonce := payload[16:28]
	ciphertext := payload[28:]

	// 3. Derive the key using the extracted salt
	key := DeriveKey(password, salt, 3, 64*1024, 4)
	defer secureWipe(key)

	// 4. Decrypt by XORing the ciphertext with the keystream
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += 64 {
		end := min(i+64, len(ciphertext))

		// Calculate which block we are on (matches the Encrypt logic)
		blockCount := uint32(i / 64)
		keyStream := generateKeyStream(key, nonce, blockCount)

		// XOR the ciphertext chunk with the keystream
		for j := i; j < end; j++ {
			plaintext[j] = ciphertext[j] ^ keyStream[j-i]
		}
	}

	return plaintext, nil
}

func (c *ChaCha20Provider) Description() ProviderInfo {
	return ProviderInfo{
		ID:          c.AlgorithmID(),
		Description: "ChaCha20 encryption (unauthenticated)",
		Secure:      false,
	}
}

func init() {
	if err := Register(&ChaCha20Provider{}); err != nil {
		panic(err)
	}
}
