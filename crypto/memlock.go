package crypto

import (
	"fmt"
	"runtime"
)

// LockedBytes represents a byte slice that is locked in memory and cannot be swapped to disk.
type LockedBytes struct {
	data []byte
}

// NewLockedBytes allocates a new byte slice, locks it in memory, and returns a LockedBytes wrapper.
func NewLockedBytes(size int) (*LockedBytes, error) {
	data := make([]byte, size)
	if err := LockMemory(data); err != nil {
		return nil, err
	}
	return &LockedBytes{data: data}, nil
}

// NewLockedBytesFrom creates a LockedBytes from existing data and locks it.
func NewLockedBytesFrom(src []byte) (*LockedBytes, error) {
	data := make([]byte, len(src))
	copy(data, src)
	if err := LockMemory(data); err != nil {
		// Securely wipe the unprotected copy before returning
		secureWipe(data)
		return nil, err
	}
	return &LockedBytes{data: data}, nil
}

// Bytes returns the underlying byte slice. The returned slice must not be used
// after the LockedBytes is unlocked or garbage collected.
func (lb *LockedBytes) Bytes() []byte {
	return lb.data
}

// Len returns the length of the locked bytes.
func (lb *LockedBytes) Len() int {
	return len(lb.data)
}

// Unlock explicitly unlocks the memory and securely wipes the data.
// This should be called when the data is no longer needed.
func (lb *LockedBytes) Unlock() error {
	if lb.data == nil {
		return nil
	}
	// Securely wipe the data first
	secureWipe(lb.data)
	// Then unlock from kernel
	if err := UnlockMemory(lb.data); err != nil {
		return err
	}
	lb.data = nil
	return nil
}

// secureWipe overwrites the data with zeros before it's freed.
// This ensures sensitive data is not left in memory.
func secureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
	// Hint to prevent compiler optimizations from removing the wipe
	runtime.KeepAlive(data)
}

// SecureWipe securely wipes sensitive data by overwriting it with zeros.
// This should be called on passwords, keys, and other sensitive data
// before allowing them to be garbage collected.
func SecureWipe(data []byte) {
	secureWipe(data)
}

// SecureWipeString securely wipes a string by converting it to a mutable byte slice.
// Note: Go strings are immutable, so this converts to []byte which won't affect
// the original string. For best results, don't store sensitive strings.
func SecureWipeString(s string) {
	// This is a best-effort approach. For best security, avoid storing
	// sensitive data as strings entirely.
	if s != "" {
		data := []byte(s)
		secureWipe(data)
	}
}

// lockMemoryErr wraps a platform-specific memory-lock failure with a
// consistent message across LockMemory implementations.
func lockMemoryErr(err error) error {
	return fmt.Errorf("failed to lock memory: %w (this might require increasing ulimit -l)", err)
}
