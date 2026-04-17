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

- [ ] Make the CLI more user friendly and nice looking
- [ ] Adding mocks for testing
- [ ] Adding more algorithms like chacha20poly1305 and more
- [ ] Add tests
- [x] Password from Environment Variable — Read password from `ENVVAULT_PASSWORD` for CI/CD pipelines
- [ ] `envvault run` — Inject secrets directly into a process without writing to disk
- [x] Password Strength Check — Reject weak passwords during encryption
- [x] Kubernetes Secret Generator — Output secrets as a Kubernetes Secret YAML
- [x] Docker `--env-file` Compatibility — Pipe decrypted output to `docker run --env-file`
- [x] `.gitignore` Guard — Prevent accidental commits of unencrypted `.env` files
- [x] `envvault history` — Audit log of lock/unlock events
- [x] `envvault edit` — Edit encrypted vaults seamlessly in your default editor