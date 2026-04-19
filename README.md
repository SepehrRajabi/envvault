# envvault

Encrypted `.env` file manager. Lock, unlock, diff, and share environment variables securely.

## Install

```bash
go install github.com/SepehrRajabi/envvault@latest
```

## Usage

```bash
# Encrypt an .env file with a password
envvault lock .env

# Encrypt with Age public keys (no password needed)
envvault lock .env -r age1abc... -r age1xyz...

# Decrypt a vault
envvault unlock .env.vault

# Edit a vault seamlessly in your default editor
envvault edit .env.vault

# Re-encrypt a vault with a new password
envvault rotate .env.vault

# export varibales from the vault file into your environment variables
eval $(envvault export .env.vault)

# Diff two files (supports .env, .env.vault, or both)
envvault diff .env.vault .env.production

# Verify vault integrity without decrypting
envvault verify .env.vault

# Generate an Age keypair
envvault keygen

# View audit log
envvault history

# List available encryption algorithms
envvault algorithms
```

## Features

### Core
- **`lock` / `unlock`**: Encrypt and decrypt `.env` files using AES-256-GCM with Argon2id key derivation.
- **`edit`**: Open encrypted vaults in your `$EDITOR`. Decrypts to a secure temp file, re-encrypts on save.
- **`rotate`**: Re-encrypt a vault with a new password in-place. Decrypted data never touches disk.
- **`diff`**: Compare two `.env` or `.env.vault` files by key. Auto-detects vaults and caches passwords to avoid double-prompting.
- **`export`**: Export environment varibales directly from a vault file 

### Cryptography & Security
- **Plugin Architecture**: Bring your own encryption algorithm by implementing the `crypto.Provider` interface.
- **Age Encryption**: Supports `age-passphrase` (scrypt) and `age-pubkey` (X25519) algorithms out of the box.
- **Multi-Recipient Encryption**: Encrypt a vault to multiple Age public keys (`-r key1 -r key2`). Anyone with a matching private key can decrypt.
- **`keygen`**: Generate Age X25519 keypairs natively. Appends to `~/.envvault/keys.txt` automatically.
- **Password Strength**: Rejects weak passwords using `zxcvbn` during `lock` and `rotate`. Use `--allow-weak` to bypass.
- **`verify`**: Check vault structural integrity, version, and algorithm without needing a password.

### Integrations
- **`k8s`**: Generate a Kubernetes Secret YAML from a vault (`envvault k8s .env.vault -n my-secret`).
- **`docker`**: Output `KEY=VALUE` format for Docker (`envvault docker .env.vault | docker run --env-file -`).
- **`guard`**: Prevent accidental commits of unencrypted `.env` files. Updates `.gitignore` and installs a `pre-commit` hook.

### Developer Experience
- **CI/CD Ready**: Set `ENVVAULT_PASSWORD` or `AGE_IDENTITY` environment variables to skip interactive prompts.
- **`history`**: Audit log of lock, unlock, rotate, edit, k8s, and docker events stored locally in `~/.envvault/history.json`.
- **Smart Completions**: Built-in shell completions for bash, zsh, and fish with smart file filtering (e.g., only suggests `.vault` files for `unlock`).
- **Tested**: Includes a mock XOR provider for fast, deterministic unit testing of the envelope and registry.

## CI/CD Integration

Provide credentials via environment variables to bypass interactive prompts in automated environments:

```yaml
# GitHub Actions example
- name: Decrypt secrets
  env:
    ENVVAULT_PASSWORD: ${{ secrets.VAULT_PASSWORD }}
  run: envvault unlock .env.vault
```

```bash
# Decrypt to stdout for Docker
docker run --env-file <(ENVVAULT_PASSWORD="$PASS" envvault docker .env.vault) my-app
```
