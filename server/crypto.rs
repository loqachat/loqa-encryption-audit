//! Server-side encryption utilities for PII protection.
//!
//! - AES-256-GCM envelope encryption for emails
//! - HMAC-SHA256 blind index for deterministic lookups
//! - Argon2 hashing for OAuth2 secrets and webhook tokens

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;

type HmacSha256 = Hmac<Sha256>;

// ── C2: HKDF Sub-Key Derivation ────────────────────────────────
//
// The master PII key is NEVER used directly for any cryptographic operation.
// Instead, domain-separated sub-keys are derived via HMAC-SHA256 (equivalent
// to HKDF-Expand with a 1-byte counter).  This ensures cryptographic isolation:
// compromising one key domain does not affect the others.

/// Derive a 32-byte sub-key from the master key using HMAC-SHA256.
/// `label` provides domain separation (e.g., "loqa-email-enc", "loqa-email-hmac").
fn derive_subkey(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(master).expect("HMAC can take key of any size");
    mac.update(label);
    mac.update(&[0x01]); // counter byte (HKDF-Expand convention)
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

// ── AES-256-GCM Email Encryption ────────────────────────────────

/// Encrypt an email address with AES-256-GCM.
/// Returns `(ciphertext_b64, nonce_b64)`.
/// C2: Uses a derived sub-key, never the master key directly.
pub fn encrypt_email(plaintext: &str, key: &[u8; 32]) -> Result<(String, String), String> {
    let enc_key = derive_subkey(key, b"loqa-email-enc");
    let cipher = Aes256Gcm::new((&enc_key).into());

    // Generate a random 12-byte nonce
    let mut nonce_arr = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_arr);

    let nonce = Nonce::from_slice(&nonce_arr);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((B64.encode(&ciphertext), B64.encode(&nonce_arr)))
}

/// Decrypt an email address from AES-256-GCM ciphertext.
/// C2: Uses a derived sub-key, never the master key directly.
pub fn decrypt_email(
    ciphertext_b64: &str,
    nonce_b64: &str,
    key: &[u8; 32],
) -> Result<String, String> {
    let enc_key = derive_subkey(key, b"loqa-email-enc");
    let cipher = Aes256Gcm::new((&enc_key).into());
    let ciphertext = B64
        .decode(ciphertext_b64)
        .map_err(|e| format!("Invalid ciphertext base64: {}", e))?;
    let nonce_bytes = B64
        .decode(nonce_b64)
        .map_err(|e| format!("Invalid nonce base64: {}", e))?;

    if nonce_bytes.len() != 12 {
        return Err("Nonce must be 12 bytes".into());
    }

    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))
}

// ── HMAC-SHA256 Blind Index ─────────────────────────────────────

/// Compute a deterministic blind index for an email address.
/// Normalizes to lowercase + trim before hashing.
/// C2: Uses a derived sub-key so the blind-index key is isolated from encryption.
pub fn compute_email_hash(email: &str, key: &[u8; 32]) -> String {
    let hmac_key = derive_subkey(key, b"loqa-email-hmac");
    let normalized = email.to_lowercase().trim().to_string();
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
    mac.update(normalized.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

// ── Argon2 Secret Hashing ───────────────────────────────────────

/// Hash a secret (OAuth2 client secret, webhook token) with Argon2.
pub fn hash_secret(plaintext: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map_err(|e| format!("Hashing failed: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a plaintext secret against an Argon2 hash.
pub fn verify_secret(plaintext: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(plaintext.as_bytes(), &parsed)
        .is_ok()
}

// ── Utility: SHA-256 token hash (for webhook tokens) ────────────

/// Compute SHA-256 hash of a webhook token for indexed lookups.
/// Unlike Argon2, this is deterministic so we can use it in WHERE clauses.
pub fn hash_token(token: &str) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

// ── Parse hex key ───────────────────────────────────────────────

/// Parse a 64-character hex string into a 32-byte key.
pub fn parse_hex_key(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex key: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Key must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Server-managed file encryption ─────────────────────────────

/// Derive a per-file AES-256 key from the master key and file ID.
fn derive_file_key(master_key: &[u8; 32], file_id: &str) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(master_key).expect("HMAC can take key of any size");
    mac.update(b"loqa-file:");
    mac.update(file_id.as_bytes());
    let result = mac.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result.into_bytes());
    key
}

/// Encrypt file data with server-managed AES-256-GCM.
/// Returns `nonce (12 bytes) || ciphertext`.
pub fn encrypt_file_data(data: &[u8], master_key: &[u8; 32], file_id: &str) -> Result<Vec<u8>, String> {
    let file_key = derive_file_key(master_key, file_id);
    let cipher = Aes256Gcm::new((&file_key).into());

    let mut nonce_arr = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_arr);
    let nonce = Nonce::from_slice(&nonce_arr);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("File encryption failed: {e}"))?;

    // Prepend nonce to ciphertext
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_arr);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt server-managed AES-256-GCM file data.
/// Input is `nonce (12 bytes) || ciphertext`.
pub fn decrypt_file_data(encrypted: &[u8], master_key: &[u8; 32], file_id: &str) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 {
        return Err("Encrypted data too short (missing nonce)".into());
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let file_key = derive_file_key(master_key, file_id);
    let cipher = Aes256Gcm::new((&file_key).into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("File decryption failed: {e}"))
}

