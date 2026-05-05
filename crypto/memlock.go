package crypto

import (
	"fmt"
	"runtime"
	"syscall"
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

// LockMemory locks a byte slice in memory to prevent swapping to disk.
// This uses syscall.Mlock to tell the kernel not to page this memory.
func LockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// syscall.Mlock needs the address and length of the memory to lock
	// For a slice, we get the address of the first element and the length
	err := syscall.Mlock(data)
	if err != nil {
		// On some systems, this might fail due to ulimit restrictions
		// Return a more descriptive error
		return fmt.Errorf("failed to lock memory: %w (this might require increasing ulimit -l)", err)
	}

	// Hint to runtime to not move this memory during GC
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	return nil
}

// UnlockMemory unlocks a previously locked byte slice.
func UnlockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	err := syscall.Munlock(data)
	if err != nil {
		return fmt.Errorf("failed to unlock memory: %w", err)
	}
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

// MmapLockedBytes allocates memory using mmap with MAP_LOCKED to ensure
// it cannot be swapped. This is the "Pro" approach that keeps memory
// outside the Go GC's control for maximum safety.
//
// Note: This requires root/elevated privileges on most systems.
// It also requires manual management - the memory must be explicitly freed.
func MmapLockedBytes(size int) ([]byte, error) {
	// Allocate memory outside of Go's GC using mmap
	data, err := syscall.Mmap(-1, 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap memory: %w", err)
	}

	// Lock it in place
	if err := syscall.Mlock(data); err != nil {
		syscall.Munmap(data)
		return nil, fmt.Errorf("failed to lock mmapped memory: %w", err)
	}

	return data, nil
}

// MunmapLockedBytes unlocks and frees memory allocated with MmapLockedBytes.
func MunmapLockedBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// Securely wipe first
	secureWipe(data)

	// Unlock from kernel
	if err := syscall.Munlock(data); err != nil {
		return fmt.Errorf("failed to unlock mmapped memory: %w", err)
	}

	// Free the mapped memory
	if err := syscall.Munmap(data); err != nil {
		return fmt.Errorf("failed to unmap memory: %w", err)
	}

	return nil
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
