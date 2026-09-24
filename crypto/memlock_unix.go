//go:build !windows

package crypto

import (
	"fmt"
	"runtime"
	"syscall"
)

// LockMemory locks a byte slice in memory to prevent swapping to disk.
// This uses syscall.Mlock to tell the kernel not to page this memory.
func LockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// syscall.Mlock needs the address and length of the memory to lock
	// For a slice, we get the address of the first element and the length
	if err := syscall.Mlock(data); err != nil {
		// On some systems, this might fail due to ulimit restrictions
		return lockMemoryErr(err)
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

	if err := syscall.Munlock(data); err != nil {
		return fmt.Errorf("failed to unlock memory: %w", err)
	}
	return nil
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
