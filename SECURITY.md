# Security Guide

## Disclosed Vulnerabilities

Write-ups of security issues found in envvault, along with the scenario that
triggered them and the fix that shipped, live in [`docs/vulns/`](docs/vulns).
Each file documents one issue end-to-end: how it was found, a reproducible
PoC, and how it was fixed (with pointers to the relevant source).

- [`vault-substitution-attack.md`](docs/vulns/vault-substitution-attack.md) —
  a vault file overwritten with content encrypted under the victim's own
  public key was silently accepted by `unlock`/`export`/`run`, since nothing
  bound a vault to the specific `lock` operation that produced it. Fixed by
  pinning the expected algorithm/recipients at lock time and checking every
  subsequent read against that pin (`crypto/trust.go`, `cmd/trust.go`).

## Memory Hardening

envvault locks decrypted plaintext and passwords in RAM to prevent the OS
from writing them to swap space (or the page file, on Windows) while a
command is running. This doesn't make secrets un-leakable — see
[What Memory Locking Does NOT Protect](#what-memory-locking-does-not-protect)
— but it closes off one real exposure path: a decrypted vault ending up
readable from a swap file or hibernation image days later.

### Key Components

1. **`crypto/memlock.go`** — Platform-independent core: the `LockedBytes`
   wrapper, `NewLockedBytes`/`NewLockedBytesFrom`, and `SecureWipe`
   (zeroes a byte slice before it's freed/garbage collected).
2. **`crypto/memlock_unix.go`** (`!windows`) — `LockMemory`/`UnlockMemory`
   via `syscall.Mlock`/`Munlock`; `MmapLockedBytes`/`MunmapLockedBytes` via
   `syscall.Mmap` + `Mlock` for allocating memory outside Go's GC entirely.
3. **`crypto/memlock_windows.go`** (`windows`) — `LockMemory`/`UnlockMemory`
   via `windows.VirtualLock`/`VirtualUnlock`. `MmapLockedBytes`/
   `MunmapLockedBytes` are **not implemented on Windows** (return an error);
   nothing in envvault currently calls them, so this doesn't affect any
   command — only `LockedBytes` (via `LockMemory`/`UnlockMemory`) is used
   in practice.
4. **`crypto/decrypt_secure.go`** — Secure decryption helpers. `DecryptSecure`
   is the one actually used throughout the codebase: every command that
   reads a vault (`unlock`, `edit`, `rotate`, `run`, `export`, `docker`,
   `k8s`, `keys add`/`remove`, `migrate`, `share`, `schema init`/`generate`,
   `check`, `get`/`set`/`unset`/`rename` via `loadEnvDocument`) follows the
   same pattern: `getVaultCredentials` → `defer crypto.SecureWipe(password)`
   → `crypto.DecryptSecure(data, password, provider)` → `defer
   lockedPlaintext.Unlock()`. `run` additionally uses `GetPasswordLocked` to
   read a password straight into locked memory instead of a plain `[]byte`.
   `DecryptWithPassword`, `DecryptWithMetadata`, `BatchDecryptSecure`,
   `DecryptToString`, and `DecryptAndLock` are exported convenience
   functions **not currently called by any command** — available library
   API, not part of the live request path.
5. **`crypto/keyderive_secure.go`** — `DeriveKeyLocked`, `CompareKeysSecure`,
   `EncryptWithLockedKey`. **None of these are used anywhere in the
   codebase today.** `EncryptWithLockedKey` in particular is an unfinished
   stub — it returns the key bytes unmodified instead of encrypting
   anything. Don't use it as-is if you're extending envvault; it needs a
   real implementation first.

### The Pattern Every Vault-Reading Command Follows

```go
password, err := getVaultCredentials(data, filePath) // prompt, keyring, or age identity
if err != nil {
    return err
}
defer crypto.SecureWipe(password)

lockedPlaintext, err := crypto.DecryptSecure(data, password, provider)
if err != nil {
    return fmt.Errorf("decryption failed: %w", err)
}
defer lockedPlaintext.Unlock()

// use lockedPlaintext.Bytes() — never copy it into a plain []byte or string
// that outlives this function without wiping it too
```

`getVaultCredentials` (`cmd/utils.go`) resolves the password from, in order:
the OS keyring (if a key was stored via `login`), a Shamir share prompt for
`shamir-aes256gcm` vaults, or an interactive password prompt — and returns
an empty byte slice for `age-pubkey` vaults, since those decrypt using the
identity file instead of a password.

### Verifying mlock Support

`envvault doctor` includes a `Memory lock (mlock)` check that round-trips a
32-byte `LockedBytes` allocation — this is the quickest way to confirm
memory locking actually works in your environment, on any platform:

```bash
envvault doctor
```

For deeper inspection:

```bash
# Linux: confirm the syscalls fire and check locked memory accounting
strace -e mlock,munlock envvault edit prod.env.vault
cat /proc/$(pidof envvault)/status | grep VmLck

# Any Unix: test behavior under a tight mlock ulimit
ulimit -l 64 && envvault edit prod.env.vault
```

Windows has no direct equivalent to `strace`/`/proc`; `envvault doctor` is
the primary way to confirm `VirtualLock` is working there.

## Performance Considerations

1. **mlock limits**: on many Unix systems the default ulimit for locked
   memory is small (often 64KB). Increase it with `ulimit -l unlimited` or
   via `/etc/security/limits.conf` if you're locking larger payloads.
2. **GC pressure**: locking memory can increase GC pressure slightly.
   Regular `LockedBytes` (via `DecryptSecure`) is fine for the vault sizes
   envvault deals with; `MmapLockedBytes` exists for allocating outside the
   GC entirely, but nothing in envvault currently uses it.
3. **Overall cost**: `mlock`/`VirtualLock` add negligible overhead compared
   to the Argon2id key derivation `lock`/`unlock` already perform.

## Security Notes

### What Memory Locking Protects

✅ Prevents the OS from swapping decrypted secrets to disk (swap/page file)
✅ Reduces exposure to cold-boot attacks
✅ Reduces exposure from physical memory dumps taken during operation

### What Memory Locking Does NOT Protect

❌ Does not protect against privileged code execution on the same machine
❌ Does not protect against kernel-level memory access
❌ Does not prevent timing attacks
❌ Does not protect unencrypted copies you make yourself — always
  `SecureWipe` any temporary plaintext copy, and avoid `string(secret)`
  conversions (Go strings are immutable and can't be wiped)

### Best Practices (for code touching secrets)

1. **Always unlock what you lock**: pair every `DecryptSecure`/
   `NewLockedBytes`/`GetPasswordLocked` call with `defer x.Unlock()`.
2. **`SecureWipe` plain `[]byte` copies**: anything decrypted or read as a
   password that isn't already a `LockedBytes`.
3. **Avoid strings for secrets**: they're immutable and can't be wiped; use
   `[]byte`.
4. **Let credentials go out of scope quickly**: don't hold a password in a
   long-lived variable or struct field longer than necessary.
5. **Be aware mlock failures are currently fatal, not degraded**: if
   `LockMemory` fails (e.g. under a restrictive `ulimit -l`, or on a
   platform/container without the privilege), `NewLockedBytesFrom` returns
   an error that propagates all the way up through `DecryptSecure` — every
   vault-reading command fails outright rather than falling back to
   unlocked memory. Run `envvault doctor` beforehand to catch this proactively
   (its `Memory lock (mlock)` check surfaces the same failure without
   touching a real vault); if you're changing this behavior, decide
   deliberately whether a fallback to unlocked memory is an acceptable
   trade-off for availability before adding one.
