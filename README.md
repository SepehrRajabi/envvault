# envvault

Encrypted `.env` file manager. Lock, unlock, diff, and share environment variables securely across your team.

> [!WARNING]
> **⚠️ v0.0.3 Early Beta Release**
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
8. [Environment Variables](#environment-variables)
9. [Common Workflows](#common-workflows)
10. [Security Considerations](#security-considerations)
11. [Limitations & Roadmap](#limitations--roadmap)
12. [Contributing](#contributing)

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

Encrypt an `.env` file into a `.env.vault` file. `encrypt` is an alias for `lock`.

**Usage:**

```bash
envvault lock [file]
envvault encrypt [file]
```

**Flags:**

- `-a, --algorithm <name>`: Encryption algorithm (default: aes256gcm-argon2id)
- `-r, --recipient <pubkey>`: Age public key for encryption (use multiple times for multiple recipients)
- `--shares <number>`: Number of Shamir shares to generate (default: 5)
- `--threshold <number>`: Minimum shares needed to recover secret (default: 3)
- `--shares-dir <path>`: Directory to save Shamir share files
- `--allow-weak`: Allow weak passwords (not recommended)
- `--allow-insecure`: Allow insecure algorithms (only for testing)
- `--no-trust`: Don't pin this vault's algorithm/recipients as trusted (see [trust](#trust)); by default, `lock` pins them automatically
- `--list-algorithms`: List available algorithms and exit

**Details:**

- Unless `--no-trust` is passed, `lock` pins the resulting vault's algorithm (and recipients, for `age-pubkey`) as its trusted baseline — see [trust](#trust) for how this is used to detect substitution later

**Examples:**

```bash
# Encrypt with password
envvault lock .env

# Encrypt with Age public key (no password)
envvault lock .env -r age1abc... -r age1xyz...

# Encrypt with Shamir secret sharing (5 shares, threshold 3)
envvault lock .env --algorithm shamir-aes256gcm --shares 5 --threshold 3 --shares-dir ./shares
```

---

### unlock

Decrypt a `.env.vault` file back to `.env`. `decrypt` is an alias for `unlock`.

**Usage:**

```bash
envvault unlock [vault-file]
envvault decrypt [vault-file]
```

**Flags:**

- `-o, --output <path>`: Output file path (default: remove `.vault` suffix)
- `--request-access`: For `shamir-aes256gcm` vaults, submit a share toward quorum instead of decrypting directly (see below)
- `--share <share>`: Shamir share to submit with `--request-access` (prompts if omitted)

**Details:**

- Checks the vault against its pinned [trust](#trust) record (if any) before decrypting, to detect a file substituted on disk

**Examples:**

```bash
# Decrypt to default output file
envvault unlock .env.vault

# Decrypt to custom file
envvault unlock .env.vault -o .env.local

# Uses OS keystore if key is stored (no password prompt)
envvault unlock .env.vault

# Submit a Shamir share toward quorum decryption instead of decrypting alone
envvault unlock backup.env.vault --request-access --share "AbC123..."
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

### migrate

Change the encryption algorithm of an existing vault file in-place (or to a new file).

**Usage:**

```bash
envvault migrate [vault-file]
```

**Flags:**

- `--from <name>`: Current encryption algorithm (optional; auto-detected from the vault header if omitted)
- `--to <name>`: New encryption algorithm (optional; defaults to the same algorithm as `--from`, which is a no-op re-encryption)
- `--output <path>`: Write the migrated vault to a new file instead of overwriting the original

**Details:**

- Decrypts with the old algorithm, then re-encrypts with the new one using the same password/recipients
- Not suitable for migrating *to* `age-pubkey` — that requires recipients, not a password; use `lock`/`edit -r` for that instead

**Examples:**

```bash
# Migrate a vault to a different algorithm in-place
envvault migrate .env.vault --to chacha20poly1305

# Migrate to a new output file, leaving the original untouched
envvault migrate .env.vault --to aes256gcm-argon2id --output migrated.env.vault
```

---

### diff

Compare two `.env` or `.env.vault` files by key. **Values are shown by default** — pass `--redacted` explicitly if you don't want plaintext values in terminal output or CI logs.

**Usage:**

```bash
envvault diff [file1] [file2]
```

**Flags:**

- `--keys-only`: Show only added, removed, and changed key names (no values, redacted or not)
- `--values`: Show plaintext values in the diff output (this is already the default; kept for explicitness)
- `--redacted`: Redact values in the diff output (default: `false` — values are shown unless this is passed)
- `--json`: Output a machine-readable JSON diff

**Examples:**

```bash
# Compare two vault files (values shown by default)
envvault diff .env.vault .env.prod.vault

# Compare vault and plain text file, redacting values for a CI log
envvault diff .env.vault .env.local --redacted

# Show only changed key names
envvault diff .env.vault .env.prod.vault --keys-only

# Output JSON for automation, values shown by default
envvault diff .env.vault .env.prod.vault --json

# Output JSON with values redacted
envvault diff .env.vault .env.prod.vault --json --redacted
```

---

### export

Export environment variables from a vault in shell format.

**Usage:**

```bash
envvault export [vault-file]
```

**Examples:**

```bash
# Export as shell commands
eval $(envvault export .env.vault)
```

---

### get

Read a single environment variable from a plain `.env` file or encrypted vault.

**Usage:**

```bash
envvault get [envfile / vaultfile] [key]
```

**Examples:**

```bash
envvault get .env API_KEY
envvault get .env.vault DATABASE_URL
```

---

### set

Set or add an environment variable in a plain `.env` file or encrypted vault.

**Usage:**

```bash
envvault set [envfile / vaultfile] [key] [value]
```

**Flags:**

- `-r, --recipient <pubkey>`: Age public key for re-encrypting `age-pubkey` vaults (use multiple times for multiple recipients)

**Examples:**

```bash
envvault set .env API_KEY sk_test_...
envvault set .env.vault DEBUG true

# Re-encrypt an Age public-key vault after setting a value
envvault set .env.vault API_KEY sk_test_... -r age1abc...
```

---

### unset / remove

Remove an environment variable from a plain `.env` file or encrypted vault. `remove` is an alias for `unset`.

**Usage:**

```bash
envvault unset [envfile / vaultfile] [key]
envvault remove [envfile / vaultfile] [key]
```

**Flags:**

- `-r, --recipient <pubkey>`: Age public key for re-encrypting `age-pubkey` vaults (use multiple times for multiple recipients)

**Examples:**

```bash
envvault unset .env OLD_SECRET
envvault remove .env.vault DEBUG
```

---

### rename

Rename an environment variable key in a plain `.env` file or encrypted vault.

**Usage:**

```bash
envvault rename [envfile / vaultfile] [old-key] [new-key]
```

**Flags:**

- `-r, --recipient <pubkey>`: Age public key for re-encrypting `age-pubkey` vaults (use multiple times for multiple recipients)

**Examples:**

```bash
envvault rename .env OLD_API_KEY API_KEY
envvault rename .env.vault DB_URL DATABASE_URL
```

---

### inspect

Show metadata for a vault file without decrypting it.

**Usage:**

```bash
envvault inspect [vault-file]
```

**Flags:**

- `-j, --json`: Output vault metadata as JSON

**Examples:**

```bash
# Inspect a vault file
envvault inspect .env.vault

# Output metadata as JSON
envvault inspect .env.vault --json
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

### verify-commit

Verify the git commit signature metadata embedded in a vault (recorded automatically by `lock` when run inside a git repository).

**Usage:**

```bash
envvault verify-commit [vault-file]
```

**Details:**

- Fails if the vault has no embedded commit metadata, if the commit isn't present in the current repository, or if `git verify-commit` reports the signature as invalid
- Requires `git` on `PATH` and running from inside the repository the vault's commit belongs to

**Examples:**

```bash
envvault verify-commit .env.vault
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

### keys add

Add a new recipient to an `age-pubkey` vault and re-encrypt it in place.

**Usage:**

```bash
envvault keys add [vault-file] [name] [public-key]
```

**Flags:**

- `--role <role>`: A label for the key, shown in the confirmation message (optional; not persisted in the vault — only public keys are stored as recipients)

**Details:**

- Only works on `age-pubkey` vaults; use `envvault migrate` to convert a password vault first
- Decrypts the vault (using your own identity, since you must already be a recipient to add another), adds the new public key to the recipient set, and re-encrypts — the vault file on disk is updated
- Updates the vault's [trust](#trust) pin to match the new recipient set
- `name` is only used in the printed confirmation; recipients are identified and stored purely by public key

**Examples:**

```bash
# Add a recipient key to a vault
envvault keys add .env.vault alice age1abc...

# Add a recipient key with a role label (cosmetic only)
envvault keys add .env.vault db-service age1xyz... --role "database"
```

---

### keys remove

Remove a recipient from an `age-pubkey` vault and re-encrypt it in place.

**Usage:**

```bash
envvault keys remove [vault-file] [public-key]
```

**Details:**

- Only works on `age-pubkey` vaults
- Refuses to remove the last remaining recipient, since that would make the vault permanently undecryptable
- Updates the vault's [trust](#trust) pin to match the new recipient set

**Examples:**

```bash
# Remove a recipient by public key
envvault keys remove .env.vault age1abc...
```

---

### history

View audit log of vault operations.

History is recorded through a pluggable backend, so the log can live in a local JSON file (the default) or be forwarded to a remote HTTP collector instead. Every command that touches a vault (`lock`, `unlock`, `edit`, `rotate`, `k8s`, `docker`, `run`, `export`, `login`/`logout`, `keys add`/`remove`, `migrate`, `set`/`unset`/`rename`, `compose`) records an event through whichever backend is active.

**Usage:**

```bash
envvault history
```

**Flags:**

- `-l, --limit <number>`: Show last N entries (default: 10)
- `--clear`: Clear all history
- `--set-token <token>`: Store the auth token for the configured `http` history backend in the OS keyring

**Examples:**

```bash
# Show last 20 operations
envvault history -l 20

# Clear history
envvault history --clear
```

**Backends:**

By default, history is written to `~/.envvault/history.json`. To forward events to a remote collector instead, set the backend in `~/.config/envvault/config.toml`:

```toml
[history]
backend = "http"
endpoint = "https://history.example.com"
```

If the endpoint requires authentication, store the token in the OS keyring (it is never written to the config file):

```bash
envvault history --set-token "your-token-here"
```

The `http` backend sends `POST /events` to record an event, `GET /events?limit=N` to list them, and `DELETE /events` for `--clear`, all with a `Bearer` token if one is configured. If `backend` is set to `http` without an `endpoint`, or to an unrecognized value, envvault falls back to the local file and prints a warning — history recording is best-effort and never blocks a vault operation.

---

### algorithms

List available encryption algorithms with security ratings.

**Usage:**

```bash
envvault algorithms [--secure]
```

**Flags:**

- `-v, --verbose`: Show detailed algorithm information including descriptions
- `-s, --secure`: Show only secure algorithms
- `--json`: Output algorithms as JSON

**Examples:**

```bash
# List available algorithms
envvault algorithms

# Show only secure algorithms
envvault algorithms --secure

# Show detailed information for each algorithm
envvault algorithms --verbose

# Output algorithms as JSON
envvault algorithms --json
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

### compose

Generate a Docker Compose service YAML snippet from a plain `.env` file or encrypted vault.

**Usage:**

```bash
envvault compose [envfile / vaultfile]
```

**Flags:**

- `-s, --service <name>`: Docker Compose service name (default: `app`)
- `-i, --image <image>`: Optional image to include in the generated service
- `-o, --output <path>`: Save YAML to a file instead of stdout

**Examples:**

```bash
# Generate a service snippet with environment variables
envvault compose .env.vault --service api --image myapp:latest

# Write a compose override file
envvault compose .env.vault -s api -o docker-compose.envvault.yml

# Use a plain env file as input
envvault compose .env.local -s worker
```

**Output example:**

```yaml
services:
  api:
    image: "myapp:latest"
    environment:
      DATABASE_URL: "postgres://user:pass@localhost/db"
      DEBUG: "true"
```

---

### k8s

Generate a Kubernetes Secret YAML from a vault.

**Usage:**

```bash
envvault k8s [vault-file]
```

**Flags:**

- `-n, --name <name>`: Secret name (default: `my-app-secret`)
- `-s, --namespace <namespace>`: Kubernetes namespace (default: `default`)
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

### config

View, initialize, or reset envvault's configuration.

**Usage:**

```bash
envvault config
```

**Flags:**

- `--show`: Show configuration (default)
- `--init`: Initialize config file with defaults
- `--reset`: Reset config to defaults
- `--path`: Print the config file path

**Config file location:**

By default, config is read from and written to `~/.config/envvault/config.toml`. To use a different file, either pass `--config` (a persistent flag available on every command, not just `config`) or set the `ENVVAULT_CONFIG` environment variable. `--config` takes precedence over `ENVVAULT_CONFIG`, which takes precedence over the default location.

```bash
# Point a single command at a custom config file
envvault --config ./ci-config.toml lock .env

# Point every envvault invocation in this shell at a custom config file
export ENVVAULT_CONFIG=/etc/envvault/config.toml
envvault config --show
```

This is useful for CI matrices or multi-project setups where different config (e.g. `[history]` backend, default algorithm) needs to apply without touching `~/.config/envvault/config.toml`.

---

### check

Check an `.env` file or vault against a schema.

The schema supports:

- `required` to enforce mandatory keys
- type tokens: `string` / `str`, `number`, `integer` / `int`, `unsigned` / `uint`, `float`, `boolean` / `bool`
- string length constraints with `len<N>`, `len<N-M>`
- numeric ranges with `min-max`
- enum constraints with `enum(value1,value2,...)`
- regex constraints with `regex(pattern)`

**Usage:**

```bash
envvault check [schemafile] [envfile / vaultfile]
# or
envvault schema check [schemafile] [envfile / vaultfile]
```

**Flags:**

- `--strict`: Fail if the env file contains keys not defined in the schema

**Schema example:**

```text
DATABASE_URL = required, str, len2-200, regex(^postgres://)
PORT = required, uint, 20-65550
NODE_ENV = required, str, enum(development,staging,production)
```

**Examples:**

```bash
# Check a vault against schema
envvault check prod.envschema .env.vault

# Check a plain .env file against schema
envvault check .envschema .env

# Fail if .env contains keys not listed in .envschema
envvault check .envschema .env --strict

# Same validation via the schema command group
envvault schema check .envschema .env --strict
```

---

### schema check

Check an `.env` file or vault against a schema. This is equivalent to the top-level `check` command and exists for users who prefer all schema-related operations under `envvault schema`.

**Usage:**

```bash
envvault schema check [schemafile] [envfile / vaultfile]
```

**Flags:**

- `--strict`: Fail if the env file contains keys not defined in the schema

---

### schema init

Create a starter `.envschema` file. If an env file or vault is provided, infer the schema from that file instead of writing the default template.

**Usage:**

```bash
envvault schema init [envfile / vaultfile]
```

**Flags:**

- `-o, --output <path>`: Schema file to write (default: `.envschema`)
- `-f, --force`: Overwrite an existing schema file
- `--optional`: When an input file is provided, generate optional rules instead of marking every key as required
- `-a, --algorithm <name>`: Override detected algorithm for vault input

**Examples:**

```bash
# Create .envschema with example rules
envvault schema init

# Write to a custom schema path
envvault schema init -o prod.envschema

# Infer .envschema from a plain env file
envvault schema init .env

# Infer a schema from an encrypted vault
envvault schema init .env.vault -o prod.envschema
```

---

### schema generate

Generate a `.envschema` file from an existing plain `.env` file or encrypted vault.

**Usage:**

```bash
envvault schema generate [envfile / vaultfile]
```

**Flags:**

- `-o, --output <path>`: Schema file to write (default: `.envschema`)
- `-f, --force`: Overwrite an existing schema file
- `--optional`: Generate optional rules instead of marking every key as required
- `-a, --algorithm <name>`: Override detected algorithm for vault input

**Examples:**

```bash
# Generate required rules from .env
envvault schema generate .env

# Generate from an encrypted vault
envvault schema generate .env.vault -o prod.envschema

# Generate optional rules
envvault schema generate .env --optional
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
- Shows whether `DEBUG` is set, and its raw value if so

**Examples:**

```bash
# View vault file status
envvault status
```

**Output example:**

```shell
📦 Vault Status
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
File                      Algorithm            Keyring         Last Modified                      
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
prod.env.vault            aes256gcm-argon2id   ✅ Yes           2026-04-17 21:25:11                
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

🔐 Git Protection
   ✅ .gitignore configured with .env patterns
   ✅ Pre-commit hook installed

🐞 Debug Mode
   ⚠️  DEBUG not set (disabled)
```

---

### doctor

Diagnose your local envvault environment.

**Usage:**

```bash
envvault doctor
```

**Details:**

- Checks OS keyring availability with a live write/read/delete round-trip (not just whether a key happens to be stored)
- Checks for an age identity via `AGE_IDENTITY`, `~/.envvault/keys.txt`, or `~/.config/age/keys.txt`
- Resolves the editor `envvault edit` would use (`$VISUAL`, then `$EDITOR`, then the platform default — `notepad` on Windows, `vi` elsewhere) and checks it's actually on `PATH`
- Checks git protection: `.gitignore` patterns and pre-commit hook installation
- Checks memory-lock (`mlock`) support for keeping decrypted secrets out of swap
- Reports whether `DEBUG` is set and its raw value; flags it as a warning when enabled, since it bypasses the tracer-detection and insecure-provider checks in `main.go`
- Prints the current binary version and all supported algorithms (same list as `envvault algorithms`)
- Scans the current directory for vault files and flags any that fail structural verification (corrupted or tampered)
- Has no flags; ⚠️ warnings are non-fatal, only ❌ failures are counted in the summary

**Examples:**

```bash
# Run all diagnostics
envvault doctor
```

**Output example:**

```shell
🩺 envvault doctor
────────────────────────────────────────────────────────────────────────────────────────────────────
Check                        Status   Detail
────────────────────────────────────────────────────────────────────────────────────────────────────
OS keyring                   ✅ OK     available
Age identity                 ⚠️  WARN no identity file found
                                        → only needed for the age-pubkey algorithm; set AGE_IDENTITY or create ~/.envvault/keys.txt
Editor                       ✅ OK     vi (default)
.gitignore                   ✅ OK     configured with .env patterns
Git pre-commit hook          ⚠️  WARN not installed
                                        → run: envvault guard --hook
Memory lock (mlock)          ✅ OK     supported
Debug mode                   ✅ OK     DEBUG not set (disabled)
────────────────────────────────────────────────────────────────────────────────────────────────────

version: 0.0.3 beta (5f534d7be898)

🔐 Supported algorithms
  * aes256gcm-argon2id (secure)
    aes256gcm-pbkdf2 (secure)
    age-passphrase (secure)
    age-pubkey (secure)
    chacha20 (insecure)
    chacha20poly1305 (secure)
    shamir-aes256gcm (secure)

📦 Vault files
  1 vault file(s) scanned, none suspicious

All checks passed.
```

---

### version

Print the envvault version.

**Usage:**

```bash
envvault version
```

**Examples:**

```bash
envvault version
# envvault version 0.0.3 beta (5f534d7be898)
```

---

### shamir split

Split a secret into Shamir shares.

**Usage:**

```bash
envvault shamir split [secret]
```

**Flags:**

- `--shares <number>`: Number of shares (default: 5)
- `--threshold <number>`: Minimum shares needed (default: 3)
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
envvault login [vault-file]
```

**Details:**

- Stores key securely in:
  - macOS: Keychain
  - Windows: Credential Manager
  - Linux: Secret Service / GNOME Keyring
- If `[vault-file]` is provided, the key is stored for that specific file.
- If no file is provided, the key is stored as the default fallback.
- Used automatically by decrypt and run commands.

**Examples:**

```bash
# Store a default decryption key
envvault login

# Store a project-specific key for one vault file
envvault login project-a/.env.vault

# Commands now work without password for the matching vault file
envvault unlock .env.vault
envvault run .env.vault -- npm start
```

---

### logout

Remove decryption key from OS keystore.

**Usage:**

```bash
envvault logout [vault-file]
```

**Details:**

- If `[vault-file]` is provided, removes only the project-specific key stored for that file.
- If no file is provided, removes the default fallback key.

**Examples:**

```bash
# Remove the default stored key
envvault logout

# Remove a project-specific stored key
envvault logout project-a/.env.vault
```

---

## Zero-Trust Sharing Commands

### trust

Pin a vault's expected algorithm (and, for `age-pubkey` vaults, recipient set) so `unlock`/`export`/`run`/`share` can detect a vault file that's been substituted on disk with differently-encrypted content — even content the victim's own key can decrypt.

`envvault lock` pins this automatically unless run with `--no-trust`.

**Usage:**

```bash
envvault trust [vault-file]
```

**Flags:**

- `--show`: Show the current trust pin for this vault path
- `--clear`: Remove the trust pin for this vault path
- `--algorithm <name>`: Pre-register an expected algorithm (e.g. in CI, before the vault file exists) instead of pinning from an existing file
- `--recipient <pubkey>`: Pre-register an expected recipient public key (repeatable; use with `--algorithm`)

**Examples:**

```bash
# Pin a vault you just verified by other means
envvault trust .env.vault

# Inspect the current pin
envvault trust .env.vault --show

# Remove a pin
envvault trust .env.vault --clear

# Pre-register expected values before the vault file exists (e.g. in CI)
envvault trust .env.vault --algorithm age-pubkey --recipient age1...
```

---

### share

Share specific environment variables with a recipient using their Age public key.

**Usage:**

```bash
envvault share [env-file | vault-file] [VAR1] [VAR2] ... --with <recipient-pubkey>
```

**Flags:**

- `--with <pubkey>`: Recipient's Age public key (required)
- `--vars-file <path>`: Read variable names from a file (one per line)
- `--ttl`: Expire the shared payload after N seconds

**Details:**

- Reads your source file as either a plain `.env` or a `.env.vault` file
- Supports direct variable names, wildcard patterns, or a vars file
- Encrypts only the selected variables for the recipient's Age public key
- Outputs a shareable `evlt://` payload
- Recipient decrypts it with `envvault receive`

**Examples:**

```bash
# Share multiple variables from a local .env file
envvault share .env DB_PASSWORD API_KEY REDIS_URL --with age1qz...

# Share with wildcard patterns from an env file
envvault share .env "DB_*" "API_*" --with age1qz...

# Share variables from a vars file
envvault share .env --vars-file vars.txt --with age1qz...

# Share from a vault file
envvault share .env.vault API_KEY --with age1qz...
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

## Environment Variables

| Variable | Used by | Purpose |
| --- | --- | --- |
| `ENVVAULT_PASSWORD` | any command that decrypts/encrypts a password-based vault | Supplies the vault password non-interactively instead of prompting, for CI and scripted use (`docker`, `k8s`, `run`, etc.) |
| `ENVVAULT_CONFIG` | every command | Overrides the config file path, taking precedence over the default `~/.config/envvault/config.toml`. The `--config` flag takes precedence over this |
| `ENVVAULT_DEFAULT_PROVIDER` | startup (before any command runs) | Overrides the default encryption algorithm/provider (falls back to `aes256gcm-argon2id` if unset or unrecognized) |
| `AGE_IDENTITY` | commands operating on `age-pubkey` vaults | The Age private key itself (an `AGE-SECRET-KEY-...` string, not a file path) used to decrypt without a password. Falls back to `~/.envvault/keys.txt`, then `~/.config/age/keys.txt`, if unset |
| `DEBUG` | startup (before any command runs) | Set to `1`/`true` to allow running under a debugger/tracer and to downgrade the insecure-default-provider check from a hard exit to a warning. Unset (or any other value) enforces both checks strictly |
| `VISUAL` / `EDITOR` | `envvault edit` | Selects the editor used to edit a decrypted vault in place (`VISUAL` takes precedence over `EDITOR`); standard Unix convention, not envvault-specific |

**Examples:**

```bash
# Decrypt non-interactively in CI
ENVVAULT_PASSWORD=$CI_VAULT_PASSWORD envvault run .env.vault -- npm test

# Point every envvault command in this shell at a custom config file
export ENVVAULT_CONFIG=/etc/envvault/config.toml

# Decrypt an age-pubkey vault using a specific private key, without a keys.txt file
AGE_IDENTITY="AGE-SECRET-KEY-1..." envvault unlock .env.vault

# Allow running under a debugger without tripping the anti-tracing check
DEBUG=1 dlv exec ./envvault -- unlock .env.vault
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
envvault share .env.vault API_KEY WEBHOOK_SECRET --with $CONTRACTOR_KEY

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
- **Audit logging**: `envvault history` tracks all operations, either in a local file or a remote HTTP collector
- **Integrity verification**: `envvault verify` detects corruption without password
- **OS keystore**: `envvault login` stores keys securely
- **Zero-trust sharing**: Share only what's needed without full file access

---

## Security Considerations

envvault follows a local-first, zero-trust philosophy. All encryption and decryption happens on your machine. There is no cloud service or central authority.

for more info, see [SECURITY](SECURITY.md)

## Limitations & Roadmap

### Current Limitations

- Temporary files are used during `edit` (deleted after use, but still a theoretical risk)
- Shamir shares are written to disk by default
- Limited real-world battle testing

### Roadmap

- Pre-built binaries and Homebrew formula (via GoReleaser)
- Improved documentation and examples
- Possible future support for hardware security keys (YubiKey/PIV)

## Contributing

Interested in contributing to envvault? Please read the **[Contributing Guidelines](CONTRIBUTING.md)** to get started.

## License

MIT
