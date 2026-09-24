//go:build windows

package crypto

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func addrLen(data []byte) (uintptr, uintptr) {
	return uintptr(unsafe.Pointer(&data[0])), uintptr(len(data))
}

// LockMemory locks a byte slice in memory to prevent swapping to disk,
// using VirtualLock (the Windows equivalent of POSIX mlock).
func LockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	addr, length := addrLen(data)
	if err := windows.VirtualLock(addr, length); err != nil {
		return lockMemoryErr(err)
	}
	return nil
}

// UnlockMemory unlocks a previously locked byte slice.
func UnlockMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	addr, length := addrLen(data)
	if err := windows.VirtualUnlock(addr, length); err != nil {
		return fmt.Errorf("failed to unlock memory: %w", err)
	}
	return nil
}

// MmapLockedBytes is not implemented on Windows; it's only used by the
// unexported "Pro" GC-bypass path, which nothing in envvault currently
// calls. LockMemory/UnlockMemory (used by LockedBytes) work normally.
func MmapLockedBytes(size int) ([]byte, error) {
	return nil, fmt.Errorf("MmapLockedBytes is not supported on Windows")
}

// MunmapLockedBytes is not implemented on Windows. See MmapLockedBytes.
func MunmapLockedBytes(data []byte) error {
	return fmt.Errorf("MunmapLockedBytes is not supported on Windows")
}
