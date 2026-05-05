# 🤝 Contributing

First off, thank you for considering contributing to **envvault**! Whether it's a bug report, a new feature, a security enhancement, or better documentation—every contribution helps keep developers' secrets safe.
I am a (somewhat busy) student at the moment, so i will do my best reviewing PRs and issues.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Workflow](#development-workflow)
3. [Adding a New Encryption Algorithm](#adding-a-new-encryption-algorithm)
4. [Coding Standards](#coding-standards)
5. [Reporting Bugs & Security Vulnerabilities](#reporting-bugs--security-vulnerabilities)

***

### Getting Started

**Prerequisites:**

* [Go](https://go.dev/dl/) (version 1.26 or higher)
* Git

**Setup:**

1. Fork the repository and clone it locally:

    ```bash
    git clone https://github.com/SepehrRajabi/envvault.git
    cd envvault
    ```

2. Build the binary to ensure everything works:

    ```bash
    go build -o envvault .
    ```

***

### Development Workflow

1. **Create a branch:** Branch out from `main` using a descriptive name.

    ```bash
    git checkout -b feat/add-aws-kms-support
    # or
    git checkout -b fix/diff-color-bug
    ```

2. **Make your changes:** Write your code and update/add tests.
3. **Test thoroughly:** Ensure all tests pass and run `go vet ./...`.
4. **Commit:** I encourage using [Conventional Commits](https://www.conventionalcommits.org/) (e.g., `feat: ...`, `fix: ...`, `docs: ...`).
5. **Submit a Pull Request:** Open a PR against the `main` branch. Fill out the PR template clearly explaining *what* changed and *why*.

***

### Adding a New Encryption Algorithm

envvault is designed to be extensible. If you want to add a new encryption algorithm (e.g., AWS KMS, Google Cloud KMS, NaCl):

1. Create a new file in the `crypto/` directory (e.g., `crypto/chacha.go`).
2. Implement the standard `Provider` interface:

    ```go
    type Provider interface {
        // AlgorithmID returns a unique identifier (e.g., "aes256gcm-argon2id", "chacha20poly1305")
        // Rules: lowercase, alphanumeric + hyphens only, max 32 chars.
        AlgorithmID() string

        // Encrypt transforms plaintext into ciphertext using the password.
        // The returned payload should contain everything needed for decryption
        // (salt, nonce, ciphertext, etc.) but NOT the envelope metadata.
        Encrypt(plaintext, password []byte) (payload []byte, err error)

        // Decrypt reverses the encryption. Payload is the raw bytes returned by Encrypt.
        Decrypt(payload, password []byte) (plaintext []byte, err error)

        // Optional description for the encryption.
        Description() ProviderInfo
    }

    // Netadata about an algorithm
    type ProviderInfo struct {
        ID          string
        Description string
        Secure      bool
    }
    ```

3. Register your algorithm in the main CLI command router so it becomes available via the `algorithms` command.
4. **Crucial:** Add test vectors in `crypto/kms_test.go` to verify encryption/decryption cycles.

***

### Coding Standards

* **Security First:** Because envvault handles secrets, never log plaintext values, keys, or environment variables. Always sanitize outputs in logs and audit trails.
* **Error Handling:** Handle errors explicitly. Do not use `panic()` in the CLI flow; return errors up the stack so the CLI can display them cleanly to the user.
* **Formatting:** Run `gofmt -w .` and `goimports -w .` before committing.
* **Linting:** Ensure your code passes `golangci-lint run`.
* **No CGO (if possible):** To keep envvault a single, static, cross-platform binary, avoid introducing CGO dependencies unless absolutely necessary (e.g., for specific OS keychain features).

***

### Reporting Bugs & Security Vulnerabilities

* **Bug Reports:** Please use the GitHub Issue Tracker. Include your OS, `envvault` version, steps to reproduce, and expected vs. actual behavior.
* **Security Vulnerabilities:** **Please do not report security vulnerabilities via public GitHub issues.** If you discover a flaw in the encryption, key handling, or memory management, please report it responsibly via <sepehrrajabi478@gmail.com>. I will acknowledge your report within 48 hours and work with you to coordinate a fix and disclosure.
