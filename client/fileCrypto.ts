/**
 * File-level E2EE — AES-256-GCM encryption for file attachments.
 *
 * Flow:
 *  1. Sender generates a random per-file AES-256-GCM key
 *  2. Encrypts file bytes with that key
 *  3. Wraps (encrypts) the per-file key using the pairwise shared secret
 *  4. Uploads ciphertext + wrapped key metadata
 *  5. Recipient unwraps the per-file key and decrypts the file
 */

// ── Encrypt a file ──────────────────────────────────────────────

export interface EncryptedFile {
  /** Encrypted file bytes */
  ciphertext: Uint8Array;
  /** 12-byte AES-GCM nonce used for file encryption (base64) */
  nonce: string;
  /** The raw per-file AES-256-GCM key (kept in memory only, never sent to server) */
  fileKey: CryptoKey;
}

/**
 * Encrypt raw file bytes with a fresh random AES-256-GCM key.
 * Returns the ciphertext, nonce, and the per-file key (for wrapping).
 */
export async function encryptFile(plainBytes: Uint8Array): Promise<EncryptedFile> {
  // Generate a random per-file key
  const fileKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true, // extractable — we need to export it for wrapping
    ["encrypt", "decrypt"],
  );

  // Generate a random 12-byte nonce
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encrypt
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    fileKey,
    plainBytes as Uint8Array<ArrayBuffer>,
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    nonce: uint8ToBase64(iv),
    fileKey,
  };
}

// ── Decrypt a file ──────────────────────────────────────────────

/**
 * Decrypt file ciphertext using the per-file AES-256-GCM key.
 */
export async function decryptFile(
  ciphertext: Uint8Array,
  nonceB64: string,
  fileKey: CryptoKey,
): Promise<Uint8Array> {
  const iv = base64ToUint8(nonceB64);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as Uint8Array<ArrayBuffer> },
    fileKey,
    ciphertext as Uint8Array<ArrayBuffer>,
  );
  return new Uint8Array(plaintext);
}

// ── Key wrapping ────────────────────────────────────────────────

export interface WrappedKey {
  /** The per-file key encrypted with the shared secret (base64) */
  wrappedKey: string;
  /** 12-byte nonce used for key wrapping (base64) */
  wrapNonce: string;
}

/**
 * Wrap (encrypt) the per-file key using a pairwise shared secret.
 * Uses AES-256-GCM with a fresh nonce.
 */
export async function wrapFileKey(
  fileKey: CryptoKey,
  sharedSecret: CryptoKey,
): Promise<WrappedKey> {
  // Export the per-file key to raw bytes
  const rawKey = await crypto.subtle.exportKey("raw", fileKey);

  // Encrypt the raw key bytes with the shared secret
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    sharedSecret,
    rawKey,
  );

  return {
    wrappedKey: uint8ToBase64(new Uint8Array(wrapped)),
    wrapNonce: uint8ToBase64(iv),
  };
}

/**
 * Unwrap (decrypt) the per-file key using a pairwise shared secret.
 * Returns a non-extractable CryptoKey for decryption.
 */
export async function unwrapFileKey(
  wrappedKeyB64: string,
  wrapNonceB64: string,
  sharedSecret: CryptoKey,
): Promise<CryptoKey> {
  const wrappedBytes = base64ToUint8(wrappedKeyB64);
  const iv = base64ToUint8(wrapNonceB64);

  // Decrypt the wrapped key
  const rawKey = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as Uint8Array<ArrayBuffer> },
    sharedSecret,
    wrappedBytes as Uint8Array<ArrayBuffer>,
  );

  // Import as a non-extractable AES-GCM key
  return crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
}

// ── Helpers ─────────────────────────────────────────────────────

/** Encode Uint8Array → base64 string */
export function uint8ToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** Decode base64 string → Uint8Array */
export function base64ToUint8(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
