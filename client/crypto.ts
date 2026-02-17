// E2EE crypto utilities — X25519 ECDH + AES-256-GCM
// Uses the Web Crypto API (SubtleCrypto)

/**
 * Generate an X25519 keypair for ECDH key agreement.
 * Falls back to P-256 ECDH if X25519 is not supported.
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  try {
    return await crypto.subtle.generateKey(
      { name: "X25519" } as any,
      false,
      ["deriveBits"]
    );
  } catch {
    // Fallback: P-256 ECDH (broader browser support)
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );
  }
}

/**
 * Export a public key to raw bytes, then base64-encode.
 */
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

/**
 * Import a base64-encoded public key.
 */
export async function importPublicKey(base64: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  try {
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "X25519" } as any,
      true,
      []
    );
  } catch {
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  }
}

/**
 * Derive a shared AES-256-GCM key from our private key + their public key.
 */
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<CryptoKey> {
  const algo = (privateKey.algorithm as any).name || "X25519";

  const bits = await crypto.subtle.deriveBits(
    { name: algo, public: publicKey } as any,
    privateKey,
    256
  );

  // HKDF to derive AES key from raw shared secret
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    bits,
    "HKDF",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32), // static salt (OK for Phase 1)
      info: new TextEncoder().encode("loqa-e2ee-dm"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns base64-encoded ciphertext and nonce.
 */
export async function encrypt(
  plaintext: string,
  key: CryptoKey
): Promise<{ ciphertext: string; nonce: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    nonce: btoa(String.fromCharCode(...iv)),
  };
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * Inputs are base64-encoded.
 */
export async function decrypt(
  ciphertext: string,
  nonce: string,
  key: CryptoKey
): Promise<string> {
  const iv = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
  const data = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(decrypted);
}
