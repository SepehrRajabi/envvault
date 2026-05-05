# Security Guide

This document consolidates the memory hardening documentation for envvault.
It covers secure memory locking, usage patterns, command integration, testing, and best practices.

## Overview

Memory hardening prevents the OS from writing encrypted secrets to disk (swap space/page file) by using `syscall.Mlock()` to lock memory pages in RAM.

### Key Components

1. **`crypto/memlock.go`** - Core memory locking primitives
   - `LockedBytes` - Wrapper for locked byte slices
   - `LockMemory()`/`UnlockMemory()` - Low-level locking
   - `MmapLockedBytes()`/`MunmapLockedBytes()` - Advanced mmap-based approach
   - `SecureWipe()` - Overwrite sensitive data before freeing

2. **`crypto/decrypt_secure.go`** - Secure decryption with memory locking
   - `DecryptSecure()` - Decrypt to locked memory
   - `GetPasswordLocked()` - Read password into locked memory
   - `DecryptWithPassword()` - Combined read + decrypt
   - `DecryptWithMetadata()` - Decrypt with envelope info
   - `BatchDecryptSecure()` - Efficiently decrypt multiple files

3. **`crypto/keyderive_secure.go`** - Secure key derivation
   - `DeriveKeyLocked()` - Derive keys in locked memory
   - `CompareKeysSecure()` - Constant-time key comparison

## Quick Start

### Basic Usage

```go
locked, err := crypto.DecryptSecure(data, password, provider)
if err != nil {
    return err
}
defer locked.Unlock()

plaintext := locked.Bytes()
```

### With Password Input

```go
locked, err := crypto.DecryptWithPassword(data, provider, "Enter password: ")
if err != nil {
    return err
}
defer locked.Unlock()
```

### Multiple Decryptions

```go
results, err := crypto.BatchDecryptSecure(vaults, password, provider)
if err != nil {
    return err
}
defer func() {
    for _, r := range results {
        r.Unlock()
    }
}()
```

## Files Created/Modified

### New Files (Memory Hardening Core)

- **`crypto/memlock.go`** - Core memory locking primitives
- **`crypto/decrypt_secure.go`** - Secure decryption functions
- **`crypto/keyderive_secure.go`** - Secure key derivation helpers

### Modified Files (Command Integration)

- **`cmd/edit.go`** - Use `DecryptSecure()` for decryption
- **`cmd/run.go`** - Use `GetPasswordLocked()` and `DecryptSecure()`
- **`cmd/diff.go`** - Use locked memory for password caching with `LockedBytes`

## Usage Patterns

### Pattern 1: Simple Decryption with Locking

**Before:**

```go
data, err := os.ReadFile(vaultFile)
plaintext, err := crypto.Decrypt(data, password, provider)
fmt.Println(string(plaintext))
```

**After:**

```go
data, err := os.ReadFile(vaultFile)
locked, err := crypto.DecryptSecure(data, password, provider)
if err != nil {
    return err
}
defer locked.Unlock()

fmt.Println(string(locked.Bytes()))
```

### Pattern 2: Read Password + Decrypt

**Before:**

```go
password, err := readPassword("Enter password: ")
if err != nil {
    return err
}
plaintext, err := crypto.Decrypt(data, password, provider)
// password is in plaintext memory
```

**After:**

```go
locked, err := crypto.DecryptWithPassword(data, provider, "Enter password: ")
if err != nil {
    return err
}
defer locked.Unlock()
// password and plaintext are in locked memory
```

### Pattern 3: Handling Multiple Files

**Before:**

```go
for _, file := range files {
    data, _ := os.ReadFile(file)
    result, _ := crypto.Decrypt(data, password, provider)
    process(result)
    crypto.SecureWipe(result) // May not be enough
}
```

**After:**

```go
data := make([][]byte, len(files))
for i, file := range files {
    d, _ := os.ReadFile(file)
    data[i] = d
}

results, err := crypto.BatchDecryptSecure(data, password, provider)
if err != nil {
    return err
}
defer func() {
    for _, r := range results {
        r.Unlock()
    }
}()

for _, result := range results {
    process(result.Bytes())
}
```

## Implementation in Commands

### cmd/edit.go

```go
func editCommand(filePath string) error {
    data, _ := os.ReadFile(filePath)

    locked, err := crypto.DecryptWithPassword(data, provider, "Enter vault password: ")
    if err != nil {
        return err
    }
    defer locked.Unlock()

    env, _ := envfile.Parse(locked.Bytes())
    crypto.SecureWipe(locked.Bytes())

    encrypted, _ := crypto.Encrypt(modifiedData, password, provider)
    atomicWrite(filePath, encrypted)
}
```

### cmd/run.go

```go
func runCommand(vaultFile, command string) error {
    data, _ := os.ReadFile(vaultFile)

    locked, err := crypto.DecryptSecure(data, cachedPassword, provider)
    if err != nil {
        locked, err = crypto.DecryptWithPassword(data, provider, "Enter password: ")
        if err != nil {
            return err
        }
    }
    defer locked.Unlock()

    env := envfile.Parse(locked.Bytes())
    // ... execute command with env
}
```

### cmd/check.go

```go
func checkCommand(vaultFile string) error {
    data, _ := os.ReadFile(vaultFile)

    decrypted, err := crypto.DecryptWithMetadata(data, password, provider)
    if err != nil {
        return err
    }
    defer decrypted.Close()

    fmt.Printf("Algorithm: %s\n", decrypted.Header.Algorithm)
    fmt.Printf("Commit: %v\n", decrypted.Header.Commit)
}
```

## Testing

### Verify mlock is working

```bash
strace -e mlock,munlock go run main.go edit prod.env.vault
cat /proc/$(pidof envvault)/status | grep VmLck
```

### Test with limited memory

```bash
ulimit -v 100000
go run main.go edit prod.env.vault
```

## Performance Considerations

1. **mlock Limits**: On many systems, the default ulimit for locked memory is 64KB.
   - Increase with: `ulimit -l unlimited`
   - Or set in `/etc/security/limits.conf`

2. **GC Pressure**: Locking memory can increase GC pressure.
   - Use `MmapLockedBytes()` for very sensitive data that must never be copied
   - Regular `LockedBytes` is fine for most use cases

3. **Performance Impact**:
   - mlock adds minimal overhead after allocation
   - Key derivation (Argon2id) is already time-consuming
   - Memory locking is negligible compared to cryptographic operations

## Security Notes

### What Memory Locking Protects

✅ Prevents OS from swapping secrets to disk  
✅ Protects against cold-boot attacks  
✅ Guards against physical memory dumps during operation  

### What Memory Locking Does NOT Protect

❌ Does not protect against privileged code execution  
❌ Does not protect against kernel-level memory access  
❌ Does not prevent timing attacks  
❌ Does not protect unencrypted copies (use SecureWipe)  

### Best Practices

1. **Always unlock when done**: Use `defer locked.Unlock()`
2. **Use SecureWipe**: Clear temporary plaintext copies with `SecureWipe()`
3. **Avoid strings**: Strings are immutable; use `[]byte` for secrets
4. **Passwords in functions**: Let passwords be garbage collected quickly
5. **Check limits**: Verify ulimit allows mlock
6. **Error handling**: Handle mlock errors gracefully

## Error Handling

Most mlock failures are non-fatal:

```bash
ulimit -l 32768 && envvault run .env.vault -- command
```

Some systems may require root for mlock - can still run with warnings.
