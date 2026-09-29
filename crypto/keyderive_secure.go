package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DeriveKeyLocked derives a key from a password and salt, storing the result in locked memory.
// The returned LockedBytes must be explicitly unlocked when done.
func DeriveKeyLocked(password, salt []byte, time, memory uint32, threads uint8) (*LockedBytes, error) {
	// Argon2 already produces the key, we just need to lock it
	key := argon2.IDKey(password, salt, time, memory, threads, 32)
	defer SecureWipe(key)

	lockedKey, err := NewLockedBytesFrom(key)
	if err != nil {
		SecureWipe(key)
		return nil, fmt.Errorf("failed to lock derived key: %w", err)
	}

	SecureWipe(key)
	return lockedKey, nil
}

// CompareKeysSecure compares two keys in a way that doesn't leak timing information
// and securely handles the memory.
func CompareKeysSecure(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	result := byte(0)
	for i := range key1 {
		result |= key1[i] ^ key2[i]
	}

	return result == 0
}
