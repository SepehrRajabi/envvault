// Package crypto implements envvault's encryption layer: the vault envelope
// format (header + ciphertext), pluggable encryption Providers (AES-GCM
// with Argon2id or PBKDF2, ChaCha20-Poly1305, Age, Shamir secret sharing),
// key derivation, password strength checks, in-memory secret locking
// (LockedBytes), zero-trust pinning of a vault's algorithm/recipients, and
// git commit metadata embedding.
package crypto
