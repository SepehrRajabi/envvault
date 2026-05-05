# 🚩 The EnvVault Cryptanalysis Challenge

Welcome to the `envvault` security lab.

The goal of this folder is to demonstrate the evolution of `envvault`'s security posture. Instead of just claiming the tool is "secure," I have provided a series of encrypted vaults that mirror the different versions of the project's encryption logic.

## 🎯 The Objective

Each subdirectory contains a `.env.vault` file. Inside that file is a secret environment variable containing a "flag" in the format:
`FLAG=CTF{...}`

Your goal is to recover the flag.

## 📈 The Difficulty Curve

The challenges are organized by the version of the `envvault` binary used to create them. As you move from v1 $\rightarrow$ v2 $\rightarrow$ v3, the cryptographic barriers become significantly stronger.

| Version | Difficulty | Focus | Primary Barrier |
| :--- | :--- | :--- | :--- |
| **v1.x** | 🟢 Easy $\rightarrow$ 🟡 Med | KDF & Entropy | Password Strength & Iterations |
| **v2.x** | 🟠 Hard | Memory Hardening | Argon2id & Memory Costs |
| **v3.x** | 🔴 Impossible | Public Key Infra | Age X25519 & Zero-Knowledge |

## 🛠️ Recommended Toolset

Depending on the level, you may need:

- The `envvault` binary itself (to attempt unlocks).
- Password cracking tools (e.g., **Hashcat** or **John the Ripper**).
- A hex editor (to inspect the vault headers).
- A lot of patience.

## 📜 Rules of Engagement

1. **No Spoilers:** If you find a flag, please do not post it in the Issues tab. Instead, open a discussion or reach out via [sepehrrajabi478@gmail.com/www.linkedin.com/in/sepehr-rajabi-1718b819b].
2. **Report Bugs:** If you discover a flaw in the encryption, key handling, or memory management, please report it responsibly via <sepehrrajabi478@gmail.com>. I will acknowledge your report within 48 hours and work with you to coordinate a fix and disclosure.

Good luck, and happy hacking! ⚡
