# envvault

Encrypted `.env` file manager. Lock, unlock, diff, and share environment variables securely across your team.

> **⚠️ v0.0.1 Early Beta Release**
>
> envvault is in early development. The core functionality works well and has been manually tested extensively, but:
>
> There are currently **no automated tests**
> No external security audit has been performed yet
>
> **Use at your own risk**, especially in production or with highly sensitive secrets.
>
> Feedback, bug reports, and contributions (especially tests and security review) are extremely welcome!

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Commands](#core-commands)
4. [Integration Commands](#integration-commands)
5. [Utility Commands](#utility-commands)
6. [Authentication & Keystore Commands](#authentication--keystore-commands)
7. [Zero-Trust Sharing Commands](#zero-trust-sharing-commands)
8. [Common Workflows](#common-workflows)
9. [Security Considerations](#security-considerations)
10. [Limitations & Roadmap](#limitations--roadmap)
11. [Contributing](#contributing)

---

## Installation

```bash
go install github.com/SepehrRajabi/envvault@latest
```

## Quick Start

```bash
# Encrypt an .env file
envvault lock .env

# Decrypt a vault
envvault unlock .env.vault

# Edit encrypted vault in your editor
envvault edit .env.vault

# Store key in OS keystore for passwordless access
envvault login

# Run a command with decrypted env vars
envvault run .env.vault -- npm start
```

## Core Commands

### lock

Encrypt an `.env` file into a `.env.vault` file.

**Usage:**

```bash
envvault lock [file]
```

**Flags:**

- `--algorithm <name>`: Encryption algorithm (default: aes256gcm-argon2id)
- `-r, --recipient <pubkey>`: Age public key for encryption (use multiple times for multiple recipients)
- `--shares <number>`: Number of Shamir shares to generate (default: 3)
- `--threshold <number>`: Minimum shares needed to recover secret (default: 2)
- `--shares-dir <path>`: Directory to save Shamir share files
- `--allow-weak`: Allow weak passwords (not recommended)
- `--allow-insecure`: Allow insecure algorithms (only for testing)

**Examples:**

```bash
# Encrypt with password
envvault lock .env

# Encrypt with Age public key (no password)
envvault lock .env -r age1abc... -r age1xyz...

# Encrypt with Shamir secret sharing (3 shares, threshold 2)
envvault lock .env --algorithm shamir-aes256gcm --shares 3 --threshold 2 --shares-dir ./shares
```

---

### unlock

Decrypt a `.env.vault` file back to `.env`.

**Usage:**

```bash
envvault unlock [vault-file]
```

**Flags:**

- `-o, --output <path>`: Output file path (default: remove `.vault` suffix)
- `--algorithm <name>`: Override detected algorithm

**Examples:**

```bash
# Decrypt to default output file
envvault unlock .env.vault

# Decrypt to custom file
envvault unlock .env.vault -o .env.local

# Uses OS keystore if key is stored (no password prompt)
envvault unlock .env.vault
```

---

### edit

Edit an encrypted vault in your default editor (`$EDITOR`).

**Usage:**

```bash
envvault edit [vault-file]
```

**Flags:**

- `-r, --recipient <pubkey>`: Re-encrypt with Age public keys (optional)
- `--algorithm <name>`: Override detected algorithm

**Details:**

- Decrypts vault into a temporary file
- Opens in `$EDITOR` for editing
- Re-encrypts on save with original password (or new recipients if specified)
- Safely deletes temp file after saving

**Examples:**

```bash
# Edit and re-encrypt with original password
envvault edit .env.vault

# Edit and re-encrypt with Age recipients
envvault edit .env.vault -r age1abc...
```

---

### rotate

Re-encrypt a vault with a new password.

**Usage:**

```bash
envvault rotate [vault-file]
```

**Flags:**

- `--allow-weak`: Allow weak passwords (not recommended)
- `--algorithm <name>`: Override detected algorithm

**Details:**

- Decrypts vault in memory, re-encrypts with new password
- Original file updated in-place
- Unencrypted data never touches disk

**Examples:**

```bash
# Change vault password
envvault rotate .env.vault
```

---

### diff

Compare two `.env` or `.env.vault` files by key.

**Usage:**

```bash
envvault diff [file1] [file2]
```

**Examples:**

```bash
# Compare two vault files
envvault diff .env.vault .env.prod.vault

# Compare vault and plain text file
envvault diff .env.vault .env.local
```

---

### export

Export environment variables from a vault in shell format.

**Usage:**

```bash
envvault export [vault-file]
```

**Flags:**

- `-f, --format <format>`: Output format: `shell`, `json`, `yaml` (default: shell)

**Examples:**

```bash
# Export as shell commands
eval $(envvault export .env.vault)
```

---

### inspect

Show metadata for a vault file without decrypting it.

**Usage:**

```bash
envvault inspect [vault-file]
```

**Examples:**

```bash
# Inspect a vault file
envvault inspect .env.vault
```

---

### verify

Verify vault integrity without decrypting.

**Usage:**

```bash
envvault verify [vault-file]
```

**Examples:**

```bash
# Verify vault integrity
envvault verify .env.vault
```

---

### keygen

Generate a new Age X25519 keypair.

**Usage:**

```bash
envvault keygen
```

**Flags:**

- `-o, --output <path>`: Save private key to file (default: ~/.envvault/keys.txt)

**Examples:**

```bash
# Generate keypair
envvault keygen

# Get public key for encryption
PUBLIC_KEY=$(envvault keygen)
envvault lock .env -r $PUBLIC_KEY
```

---

### history

View audit log of vault operations.

**Usage:**

```bash
envvault history
```

**Flags:**

- `-l, --limit <number>`: Show last N entries (default: 50)
- `--clear`: Clear all history

**Examples:**

```bash
# Show last 20 operations
envvault history -l 20

# Clear history
envvault history --clear
```

---

### algorithms

List available encryption algorithms with security ratings.

**Usage:**

```bash
envvault algorithms
```

**Flags:**

- `-v, --verbose`: Show detailed algorithm information including descriptions

**Examples:**

```bash
# List algorithms
envvault algorithms

# Show detailed information
envvault algorithms --verbose
```

---

## Integration Commands

### docker

Output decrypted secrets in Docker `--env-file` format.

**Usage:**

```bash
envvault docker [vault-file]
```

**Flags:**

- `-o, --output <path>`: Save to file instead of stdout

**Examples:**

```bash
# Load directly in docker run
docker run --env-file <(envvault docker .env.vault) myimage
```

---

### k8s

Generate a Kubernetes Secret YAML from a vault.

**Usage:**

```bash
envvault k8s [vault-file]
```

**Flags:**

- `-n, --name <name>`: Secret name (default: derived from filename)
- `--namespace <namespace>`: Kubernetes namespace (default: default)
- `-t, --type <type>`: Secret type (default: Opaque)
- `-o, --output <path>`: Save to file

**Examples:**

```bash
# Generate and apply to cluster
envvault k8s .env.vault | kubectl apply -f -

# Generate with custom name and namespace
envvault k8s .env.prod.vault -n my-secret --namespace production
```

---

### run

Run a command with decrypted environment variables injected in memory.

**Usage:**

```bash
envvault run [vaultfile] -- [command] [args...]
```

**Examples:**

```bash
# Run Node.js server
envvault run .env.vault -- npm start

# Run Python script
envvault run .env.vault -- python main.py --port 8080

# Run docker-compose
envvault run .env.prod.vault -- docker-compose up
```

---

## Utility Commands

### check

Check an `.env` file or vault against a schema.

**Usage:**

```bash
envvault check [schemafile] [envfile / vaultfile]
```

**Examples:**

```bash
# Check vault against schema
envvault check prod.env.schema .env.vault
```

---

### guard

Prevent accidental commits of unencrypted `.env` files.

**Usage:**

```bash
envvault guard [--init] [--hook]
```

**Flags:**

- `--init`: Update `.gitignore` with `.env` patterns
- `--hook`: Install git pre-commit hook

**Examples:**

```bash
# Initialize guards
envvault guard --init

# Install pre-commit hook
envvault guard --hook
```

---

### status

Show status of all vault files in the current directory.

**Usage:**

```bash
envvault status
```

**Details:**

- Displays all `.env*.vault` files in the current directory
- Shows encryption algorithm used for each vault
- Indicates whether a decryption key is stored in the OS keystore
- Displays last modification time for each vault file
- Shows git protection status (.gitignore configuration and pre-commit hook setup)

**Examples:**

```bash
# View vault file status
envvault status
```

**Output example:**

```

📦 Vault Status
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
File                      Algorithm            Keyring         Last Modified                      
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
prod.env.vault            aes256gcm-argon2id   ✅ Yes           2026-04-17 21:25:11                
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

🔐 Git Protection
   ✅ .gitignore configured with .env patterns
   ✅ Pre-commit hook installed
```

---

### shamir split

Split a secret into Shamir shares.

**Usage:**

```bash
envvault shamir split [secret]
```

**Flags:**

- `--shares <number>`: Number of shares (default: 3)
- `--threshold <number>`: Minimum shares needed (default: 2)
- `--out-dir <path>`: Save shares to directory

**Examples:**

```bash
# Create 5 shares, need 3 to recover
envvault shamir split "my-secret" --shares 5 --threshold 3
```

---

### shamir combine

Combine Shamir shares to recover the secret.

**Usage:**

```bash
envvault shamir combine [share1] [share2] ...
```

**Examples:**

```bash
# Combine shares
envvault shamir combine share1 share2 share3
```

---

## Authentication & Keystore Commands

### login

Store decryption key in OS keystore for passwordless access.

**Usage:**

```bash
envvault login
```

**Details:**

- Stores key securely in:
  - macOS: Keychain
  - Windows: Credential Manager
  - Linux: Secret Service / gnome-keyring
- Used automatically by decrypt commands

**Examples:**

```bash
# Store key
envvault login

# Commands now work without password
envvault unlock .env.vault
envvault run .env.vault -- npm start
```

---

### logout

Remove decryption key from OS keystore.

**Usage:**

```bash
envvault logout
```

**Examples:**

```bash
# Remove stored key
envvault logout
```

---

## Zero-Trust Sharing Commands

### share

Share specific environment variables with a recipient using their Age public key. No password needed, no sharing the entire .env file.

**Usage:**

```bash
envvault share [VAR1] [VAR2] ... --with <recipient-pubkey>
```

**Flags:**

- `--with <pubkey>`: Recipient's Age public key (required)
- `--vars-file <path>`: Read variable names from a file (one per line)
- `--env-file <path>`: Source .env file (default: .env)

**Details:**

- Extracts only specified variables from your .env file
- Encrypts them specifically for the recipient's public key
- Outputs base64 string with `evlt://` prefix
- Recipient can decrypt with `envvault receive`

**Examples:**

```bash
# Share multiple variables
envvault share DB_PASSWORD API_KEY REDIS_URL --with age1qz...

# Share with wildcard pattern
envvault share "DB_*" "API_*" --with age1qz...

# Share variables from file
# vars.txt contains one variable name per line
envvault share --vars-file vars.txt --with age1qz...

# Share from different source file
envvault share API_KEY --env-file .env.prod --with age1qz...
```

---

### receive

Decrypt variables that were shared with you.

**Usage:**

```bash
envvault receive <evlt://...>
```

**Flags:**

- `--import <path>`: Import variables into this .env file
- `--output`: Output as shell export statements (for piping)

**Details:**

- Decrypts variables encrypted for your Age identity
- Can display, import to file, or output as shell exports
- No password required (uses your Age private key)

**Examples:**

```bash
# Display shared variables
envvault receive evlt://eyJhbGciOi...

# Load into shell environment
eval "$(envvault receive evlt://eyJhbGciOi... --output)"

# Import into local .env file
envvault receive evlt://eyJhbGciOi... --import .env

# Pipe to source
envvault receive evlt://eyJhbGciOi... --output | source /dev/stdin
```

---

## Common Workflows

### Secure Team Collaboration

```bash
# 1. Generate keypair for each team member
envvault keygen

# 2. Encrypt vault with team members' public keys
envvault lock .env -r age1_member1... -r age1_member2...

# 3. Team members decrypt automatically (Age finds private key)
envvault unlock .env.vault
```

### CI/CD Pipeline

```bash
# Use environment variable for password
export ENVVAULT_PASSWORD="$CI_SECRET_PASSWORD"

# Export for application
envvault export .env.vault > .env

# Or generate K8s secret
envvault k8s .env.vault | kubectl apply -f -
```

### Development Workflow

```bash
# Store key in OS keystore once
envvault login

# Run commands without password
envvault run .env.vault -- npm start

# Edit vault seamlessly
envvault edit .env.vault
```

### Zero-Trust Sharing with Contractors/Partners

```bash
# Get the contractor's Age public key from them
CONTRACTOR_KEY="age1qz..."

# Share only specific variables they need
envvault share API_KEY WEBHOOK_SECRET --with $CONTRACTOR_KEY

# They paste the evlt:// string you send them and decrypt locally
envvault receive evlt://eyJhbGciOi... --import .env.local

# No need to share entire .env file or add them to your repo
```

### Multi-Project Key Management

```bash
# Store project-specific keys in OS keystore
envvault login project-a/.env.vault  # Stores key for project-a
envvault login project-b/.env.vault  # Stores key for project-b

# Each command automatically uses the right key
envvault run project-a/.env.vault -- npm start
envvault run project-b/.env.vault -- npm start

# No password prompts, keys stored securely per project
```

## Safety Features

- **No plaintext on disk**: `envvault run` and `envvault edit` handle decryption in memory
- **Atomic writes**: Encrypted files use atomic operations
- **Git protection**: `envvault guard` prevents commits of `.env` files
- **Audit logging**: `envvault history` tracks all operations
- **Integrity verification**: `envvault verify` detects corruption without password
- **OS keystore**: `envvault login` stores keys securely
- **Zero-trust sharing**: Share only what's needed without full file access

---

## Security Considerations

envvault follows a local-first, zero-trust philosophy. All encryption and decryption happens on your machine. There is no cloud service or central authority.

for more info, see [SECURITY](SECURITY.md)

## Limitations & Roadmap

### Current Limitations

- No automated test suite yet (highest priority)
- Temporary files are used during `edit` (deleted after use, but still a theoretical risk)
- Shamir shares are written to disk by default
- Limited real-world battle testing

### Roadmap

- Comprehensive test coverage
- Pre-built binaries and Homebrew formula (via GoReleaser)
- Improved documentation and examples
- Possible future support for hardware security keys (YubiKey/PIV)

## Contributing

Interested in contributing to envvault? Please read the **[Contributing Guidelines](CONTRIBUTING.md)** to get started.

## License

MIT
