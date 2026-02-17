# Loqa Encryption Audit

> **Complete cryptographic source code for independent security review.**

This repository contains the **8 self-contained files** that implement 100% of Loqa's encryption logic. No cryptographic decisions are made outside these files. They are published here for transparency and to enable independent audit by security researchers, cryptographers, and enterprise security teams.

📄 **Full whitepaper:** [loqa.chat/encryption](https://loqa.chat/encryption)

---

## Architecture Overview

| Surface | Protocol | Cipher | Files |
|---------|----------|--------|-------|
| **1:1 DMs** | X3DH + Double Ratchet | AES-256-GCM | `crypto.ts`, `doubleRatchet.ts`, `e2eeManager.ts` |
| **Group DMs** | Per-message key + Ratchet wrap | AES-256-GCM | `e2eeManager.ts`, `crypto.ts` |
| **Server Channels** | MLS (RFC 9420) | AES-256-GCM | `mlsManager.ts`, `mlsStorage.ts` |
| **File Attachments** | Per-file key wrapping | AES-256-GCM | `fileCrypto.ts`, `e2eeManager.ts` |
| **PII (Emails)** | Server-side envelope | AES-256-GCM + HMAC | `crypto.rs` |
| **Passwords** | Argon2id (PHC winner) | — | `crypto.rs` |
| **Stored Files** | Server-managed encryption | AES-256-GCM + HKDF | `crypto.rs` |

---

## File Map

### `client/` — Browser-side E2EE (TypeScript, Web Crypto API)

| File | Lines | Purpose |
|------|-------|---------|
| [`crypto.ts`](client/crypto.ts) | 138 | X25519/P-256 ECDH key exchange + AES-256-GCM encrypt/decrypt primitives |
| [`doubleRatchet.ts`](client/doubleRatchet.ts) | 615 | Full X3DH key agreement + Double Ratchet protocol (forward secrecy + post-compromise security) |
| [`e2eeManager.ts`](client/e2eeManager.ts) | 922 | Orchestration — DM, Group DM, and MLS file encryption flows |
| [`fileCrypto.ts`](client/fileCrypto.ts) | 145 | Per-file AES-256-GCM encryption with key wrapping/unwrapping |
| [`keystore.ts`](client/keystore.ts) | 289 | IndexedDB private key storage (proves keys never leave device) |
| [`mlsManager.ts`](client/mlsManager.ts) | 333 | OpenMLS WASM wrapper — group management, encrypt, decrypt |
| [`mlsStorage.ts`](client/mlsStorage.ts) | 114 | IndexedDB persistence for MLS group & identity state |

### `server/` — Server-side PII protection (Rust)

| File | Lines | Purpose |
|------|-------|---------|
| [`crypto.rs`](server/crypto.rs) | 208 | AES-256-GCM email encryption, HMAC-SHA256 blind indexes, Argon2id hashing, per-file encryption |

**Total auditable surface: 2,764 lines**

---

## Dependencies

### Client (TypeScript)
- **Web Crypto API** — built into all modern browsers (no external crypto libraries)
- **OpenMLS WASM** — MLS protocol implementation (compiled to WebAssembly)

### Server (Rust)
- `aes-gcm` — AES-256-GCM authenticated encryption
- `hmac` + `sha2` — HMAC-SHA256 for key derivation and blind indexes
- `argon2` — Argon2id password hashing (PHC winner)
- `rand` — Cryptographically secure random number generation

---

## How to Audit

1. **Verify a specific claim** — Search for the relevant function name in these files. Every cryptographic operation maps to a function documented in the [whitepaper](https://loqa.chat/encryption).

2. **Trace a message flow** — Start from `e2eeManager.ts` (the orchestrator), which calls into `doubleRatchet.ts` for DMs, `crypto.ts` for primitives, and `fileCrypto.ts` for attachments.

3. **Verify key isolation** — Read `keystore.ts` to confirm private keys are stored as non-extractable `CryptoKey` objects in IndexedDB and never serialized or transmitted.

4. **Verify server-side PII** — Read `crypto.rs` to confirm email addresses are encrypted with derived sub-keys (domain separation via HMAC-SHA256) and passwords use Argon2id.

---

## Reporting Issues

If you discover a security vulnerability, please report it responsibly:

- **Email:** security@loqa.chat
- **Do not** open a public GitHub issue for security vulnerabilities

We will acknowledge receipt within 48 hours and provide a timeline for remediation.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See the LICENSE file for details.

Copyright 2026 Loqa, Inc.
