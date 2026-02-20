# 🔑 ShadowKey

> **P2P Shamir's Secret Sharing — Split secrets across peers. Reconstruct only with quorum. Zero trust.**

[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D18-green)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
[![Crypto](https://img.shields.io/badge/Crypto-GF(256)%20Shamir-blueviolet)](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
[![Built for](https://img.shields.io/badge/Built%20for-Intercom%20Vibe%20Competition-orange)](https://github.com/Trac-Systems/intercom)
[![Termux Ready](https://img.shields.io/badge/Termux-Ready-brightgreen)](https://termux.dev)

---

## What is Shamir's Secret Sharing?

A cryptographic scheme where a secret is split into **N shares**. The secret can only be reconstructed when at least **K shares** are combined. **Any K-1 shares reveal mathematically nothing** about the secret.

```
Secret: "master-db-password-2026"
   │
   ▼  shamirSplit(N=5, K=3)
   │
   ├── Share 1/5  →  peer Alice
   ├── Share 2/5  →  peer Bob
   ├── Share 3/5  →  peer Charlie
   ├── Share 4/5  →  peer Diana
   └── Share 5/5  →  peer Eve

Reconstruct: any 3 peers  →  "master-db-password-2026" ✔
             any 2 peers  →  learn NOTHING              ✔
```

---

## Implementation

ShadowKey implements Shamir's Secret Sharing **from scratch** using **GF(256) Galois Field arithmetic** — the same mathematics used in hardware security modules (HSMs) and military-grade key management. Zero external crypto dependencies beyond Node.js built-in `crypto`.

---

## Installation

```bash
# Desktop
git clone 
cd shadowkey && npm install
node index.js --n 5 --k 3

# Termux
pkg update && pkg upgrade -y && pkg install nodejs git -y
git clone 
cd shadowkey && npm install
node index.js --n 3 --k 2 --session "team-vault"
```

---

## Usage

### Split a Secret

```bash
node index.js --mode split --n 5 --k 3 --session "vault-2026"
```

1. Type your secret when prompted
2. Receive 5 encoded shares printed in terminal
3. Session waits on P2P swarm for up to N peers to connect and receive their shares automatically

### Reconstruct the Secret

Each peer runs on their own machine simultaneously:

```bash
# Peer A — has share 1
node index.js --mode reconstruct --session "vault-2026" --share "01:a3f9..."

# Peer B — has share 3
node index.js --mode reconstruct --session "vault-2026" --share "03:7b2c..."

# Peer C — has share 5
node index.js --mode reconstruct --session "vault-2026" --share "05:d4e1..."
```

When K peers connect to the same session, the secret is reconstructed automatically.

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--mode` | *(menu)* | `split` or `reconstruct` |
| `--n` | `5` | Total number of shares |
| `--k` | `3` | Reconstruction threshold |
| `--session` | `default` | Named P2P session key |
| `--share` | *(none)* | Your encoded share for reconstruct mode |

---

## Share Format

```
01:a3f92b1cd8e045f7b6c2190da3e4821f...
^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
│   hex-encoded share bytes (= secret byte length)
└── share index x (1..N) as 2-digit hex
```

---

## Security Properties

| Property | Status |
|---|---|
| Information theoretic security | ✅ Any K-1 shares reveal zero information |
| No trusted dealer after split | ✅ Dealer can discard original after distribution |
| GF(256) Lagrange interpolation | ✅ Implemented from scratch |
| Transport encryption | ✅ Hyperswarm Noise protocol |
| Server dependency | ❌ None — pure P2P |
| Disk storage | ❌ Nothing written automatically |

---

## Use Cases

- Split a root CA private key across 3 engineers (2-of-3 required to sign)
- Split a crypto wallet seed across 5 family members (3-of-5 to recover)
- Split a production database password across a team (4-of-7 required)
- Split an encryption master key before a team member goes offline

---

## Trac Address

```
trac1vu3vq4g4mlyf36mlw0ul7jast0una6407cxpn64hud57x7xlnnjqpylwpm
```

## License

MIT © [INSERT_YOUR_TRAC_ADDRESS_HERE]
