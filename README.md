# envvault

> Encrypted `.env` file manager. Lock, unlock, diff, and share environment variables securely.

## Install

```bash
go install github.com/SepehrRajabi/envvault@latest
```

## Usage

```bash
# Encrypt an .env file
envvault lock .env

# Decrypt a .env.vault file
envvault unlock .env.vault

# Diff two .env files by key
envvault diff .env .env.production

# List available encryption algorithms
envvault algorithms
```

## Roadmap

- [ ] Adding mocks for testing
- [ ] Adding more algorithms like chacha20poly1305 and more
- [ ] Add tests
