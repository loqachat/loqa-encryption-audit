// E2EE Manager — high-level orchestration for DM encryption
// Connects crypto.ts + keystore.ts + doubleRatchet.ts to the application layer.

import { generateKeyPair, exportPublicKey, importPublicKey, deriveSharedSecret, encrypt, decrypt } from "./crypto";
import {
  saveKeyPair, getKeyPair, getOrCreateDeviceId,
  saveRatchetSession, getRatchetSession, getAllRatchetSessions,
  saveSignedPreKey, getLatestSignedPreKey,
  saveOTPPreKeys, getOTPPreKey, deleteOTPPreKey,
} from "./keystore";
import {
  x3dhInitiator, x3dhResponder,
  createInitiatorSession, createResponderSession,
  ratchetEncrypt, ratchetDecrypt,
  generateSignedPreKey, generateOneTimePreKeys,
  serializeHeader, parseHeader,
  type RatchetHeader, type RatchetSession, type X3DHDeviceBundle,
} from "./doubleRatchet";
import * as api from "./api";
import { devLog } from "./logger";

// ── Caches ──────────────────────────────────────────────────────
// Recipient public key cache: userId → base64 public key
const publicKeyCache = new Map<string, string>();

// Derived shared-secret cache: recipientUserId → CryptoKey
const sharedSecretCache = new Map<string, CryptoKey>();

// Our own public key (base64), set during init
let ownPublicKeyB64: string | null = null;
let ownUserId: string | null = null;
let ownDeviceId: string | null = null;

const OTP_BATCH_SIZE = 100;
const OTP_REPLENISH_THRESHOLD = 30;

// ── Initialization ──────────────────────────────────────────────

/**
 * Bootstrap E2EE on login. Generates a keypair if one doesn't exist,
 * stores it in IndexedDB, and uploads the public key to the server.
 */
export async function initE2EE(token: string, userId: string): Promise<void> {
  ownUserId = userId;

  try {
    let stored = await getKeyPair(userId);

    if (!stored) {
      // Generate fresh keypair
      const keyPair = await generateKeyPair();
      await saveKeyPair(userId, keyPair);
      stored = { userId, publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
    }

    // Export and cache our public key
    ownPublicKeyB64 = await exportPublicKey(stored.publicKey);

    // Upload identity key to server (idempotent — server just overwrites)
    try {
      await api.users.uploadKeys(token, ownPublicKeyB64);
    } catch (err) {
      console.warn("[E2EE] Failed to upload public key:", err);
    }

    // ── Double Ratchet / X3DH prekey bootstrap ──
    ownDeviceId = await getOrCreateDeviceId();
    const deviceLabel = `${navigator.userAgent.split(' ').slice(-1)[0] || 'Browser'}`;

    // Generate signed prekey if we don't have one
    let spk = await getLatestSignedPreKey();
    if (!spk) {
      const gen = await generateSignedPreKey(stored.privateKey);
      const otps = await generateOneTimePreKeys(OTP_BATCH_SIZE);

      // Upload to server
      try {
        const result = await api.users.uploadPrekeys(
          token, ownDeviceId, gen.publicKeyB64, gen.signatureB64,
          otps.publicKeysB64, deviceLabel
        );
        // Save private keys locally
        await saveSignedPreKey({
          id: result.signed_prekey_id,
          publicKeyB64: gen.publicKeyB64,
          privateKeyJwk: gen.privateKeyJwk,
          createdAt: Date.now(),
        });
        // Save OTP private keys
        const otpEntries = otps.publicKeysB64.map((pub, i) => ({
          publicKeyB64: pub,
          privateKeyJwk: otps.privateJwks[i],
        }));
        await saveOTPPreKeys(otpEntries);
        devLog("[E2EE]", "Uploaded prekeys:", result.one_time_prekeys_stored, "OTPs");
      } catch (err) {
        console.warn("[E2EE] Failed to upload prekeys:", err);
      }
    } else {
      // Re-upload existing signed prekey (device heartbeat)
      try {
        await api.users.uploadPrekeys(
          token, ownDeviceId, spk.publicKeyB64, '', [], deviceLabel
        );
      } catch {
        // non-critical
      }
    }

    // Check and replenish one-time prekeys
    try {
      const { count } = await api.users.getPrekeyCount(token, ownDeviceId);
      if (count < OTP_REPLENISH_THRESHOLD) {
        const otps = await generateOneTimePreKeys(OTP_BATCH_SIZE);
        spk = await getLatestSignedPreKey();
        if (spk) {
          await api.users.uploadPrekeys(
            token, ownDeviceId, spk.publicKeyB64, '',
            otps.publicKeysB64, deviceLabel
          );
          const otpEntries = otps.publicKeysB64.map((pub, i) => ({
            publicKeyB64: pub,
            privateKeyJwk: otps.privateJwks[i],
          }));
          await saveOTPPreKeys(otpEntries);
          devLog("[E2EE]", "Replenished", OTP_BATCH_SIZE, "OTPs");
        }
      }
    } catch {
      // non-critical
    }

    devLog("[E2EE]", "Initialized for user", userId, "device", ownDeviceId);
  } catch (err) {
    console.error("[E2EE] Initialization failed:", err);
  }
}

// ── Public Key Retrieval ────────────────────────────────────────

/**
 * Fetch a recipient's public identity key, with caching.
 */
export async function getRecipientPublicKey(
  token: string,
  recipientId: string
): Promise<string | null> {
  // Check cache first
  const cached = publicKeyCache.get(recipientId);
  if (cached) return cached;

  try {
    const user = await api.users.get(token, recipientId);
    if (user.identity_key) {
      publicKeyCache.set(recipientId, user.identity_key);
      return user.identity_key;
    }
  } catch (err) {
    console.warn("[E2EE] Failed to fetch public key for", recipientId, err);
  }
  return null;
}

// ── Shared Secret Derivation ────────────────────────────────────

/**
 * Derive (or retrieve cached) shared secret with a recipient.
 */
async function getOrDeriveSharedSecret(
  recipientId: string,
  recipientPublicKeyB64: string
): Promise<CryptoKey> {
  const cached = sharedSecretCache.get(recipientId);
  if (cached) return cached;

  if (!ownUserId) throw new Error("E2EE not initialized");

  const stored = await getKeyPair(ownUserId);
  if (!stored) throw new Error("No keypair found for current user");

  const recipientPubKey = await importPublicKey(recipientPublicKeyB64);
  const secret = await deriveSharedSecret(stored.privateKey, recipientPubKey);

  sharedSecretCache.set(recipientId, secret);
  return secret;
}

// ── Encrypt ─────────────────────────────────────────────────────

export interface EncryptedPayload {
  ciphertext: string;
  nonce: string;
  senderKeyId: string;
}

/**
 * Encrypt a plaintext message for a DM recipient (Double Ratchet).
 * Multi-device: encrypts for ALL of the recipient's devices.
 * The primary device's ciphertext goes in the standard fields;
 * additional devices are carried in the senderKeyId JSON header.
 */
export async function encryptForDm(
  token: string,
  plaintext: string,
  recipientId: string
): Promise<EncryptedPayload | null> {
  try {
    if (!ownPublicKeyB64 || !ownUserId || !ownDeviceId) {
      console.warn("[E2EE] Not initialized");
      return null;
    }

    // Get or establish ratchet sessions for all of the recipient's devices
    let sessions = await getAllRatchetSessions(recipientId);

    if (sessions.length === 0) {
      // No sessions — perform X3DH to establish them
      try {
        const bundle = await api.users.claimPrekeys(token, recipientId);
        const stored = await getKeyPair(ownUserId);
        if (!stored) throw new Error("No keypair");

        for (const dev of bundle.devices) {
          const devBundle: X3DHDeviceBundle = {
            deviceId: dev.device_id,
            identityKeyB64: bundle.identity_key,
            signedPreKeyB64: dev.signed_prekey,
            signedPreKeySigB64: dev.signed_prekey_signature,
            oneTimePreKeyB64: dev.one_time_prekey,
          };
          const { sharedSecret } = await x3dhInitiator(stored.privateKey, devBundle);
          const session = await createInitiatorSession(
            sharedSecret, dev.signed_prekey, ownDeviceId, recipientId, dev.device_id
          );
          await saveRatchetSession(recipientId, dev.device_id, session);
        }
        sessions = await getAllRatchetSessions(recipientId);
      } catch (err) {
        console.warn("[E2EE] X3DH failed, falling back to legacy ECDH:", err);
        return encryptForDmLegacy(token, plaintext, recipientId);
      }
    }

    if (sessions.length === 0) {
      console.warn("[E2EE] No ratchet sessions available");
      return encryptForDmLegacy(token, plaintext, recipientId);
    }

    // Encrypt with the first (primary) session
    const primary = sessions[0];
    const { ciphertext, nonce, header } = await ratchetEncrypt(primary, plaintext);
    await saveRatchetSession(recipientId, primary.peerDeviceId, primary);

    // Encrypt for additional devices
    const deviceKeys: Record<string, { ciphertext: string; nonce: string; header: RatchetHeader }> = {};
    for (let i = 1; i < sessions.length; i++) {
      const sess = sessions[i];
      try {
        const extra = await ratchetEncrypt(sess, plaintext);
        await saveRatchetSession(recipientId, sess.peerDeviceId, sess);
        deviceKeys[sess.peerDeviceId] = extra;
      } catch (err) {
        devLog("[E2EE]", "Failed to encrypt for device", sess.peerDeviceId, err);
      }
    }

    // Pack header with optional device keys
    const fullHeader = {
      ...header,
      ...(Object.keys(deviceKeys).length > 0 ? { deviceKeys } : {}),
    };

    return {
      ciphertext,
      nonce,
      senderKeyId: serializeHeader(fullHeader),
    };
  } catch (err) {
    console.error("[E2EE] Ratchet encryption failed:", err);
    return null;
  }
}

/** Legacy (Phase 1) static-ECDH encryption fallback */
async function encryptForDmLegacy(
  token: string,
  plaintext: string,
  recipientId: string
): Promise<EncryptedPayload | null> {
  const recipientPubKeyB64 = await getRecipientPublicKey(token, recipientId);
  if (!recipientPubKeyB64 || !ownPublicKeyB64) return null;
  const sharedSecret = await getOrDeriveSharedSecret(recipientId, recipientPubKeyB64);
  const { ciphertext, nonce } = await encrypt(plaintext, sharedSecret);
  return { ciphertext, nonce, senderKeyId: ownPublicKeyB64 };
}

// ── Decrypt ─────────────────────────────────────────────────────

/**
 * Decrypt an E2EE message. Returns the plaintext, or a fallback
 * string if decryption fails.
 * Handles both ratchet (Phase 2) and legacy (Phase 1) messages.
 */
export async function decryptDm(
  token: string,
  message: api.Message
): Promise<string> {
  if (!message.encrypted_content || !message.nonce) {
    return message.content;
  }

  try {
    const senderKeyId = message.sender_key_id;
    if (!senderKeyId) {
      return "🔒 [Encrypted — missing sender key]";
    }

    // Detect ratchet vs legacy
    const header = parseHeader(senderKeyId);
    if (header) {
      return await decryptRatchetMessage(token, message, header);
    }

    // Legacy: sender_key_id is a base64 public key
    const senderId = message.author;
    if (senderId === ownUserId) {
      return "🔒 [Encrypted message]";
    }
    const sharedSecret = await getOrDeriveSharedSecret(senderId, senderKeyId);
    return await decrypt(message.encrypted_content, message.nonce, sharedSecret);
  } catch (err) {
    console.warn("[E2EE] Decryption failed:", err);
    return "🔒 [Unable to decrypt]";
  }
}

/**
 * Decrypt a DM message with explicit knowledge of the other participant.
 * Handles both ratchet (Phase 2) and legacy (Phase 1) messages.
 */
export async function decryptDmWithRecipient(
  token: string,
  message: api.Message,
  recipientId: string
): Promise<string> {
  if (!message.encrypted_content || !message.nonce) {
    return message.content;
  }

  try {
    const senderKeyId = message.sender_key_id;
    if (!senderKeyId) {
      return "🔒 [Encrypted — missing key]";
    }

    // Detect ratchet vs legacy
    const header = parseHeader(senderKeyId);
    if (header) {
      return await decryptRatchetMessage(token, message, header);
    }

    // Legacy: static ECDH
    let peerId: string;
    let peerPubKeyB64: string | null;

    if (message.author === ownUserId) {
      peerId = recipientId;
      peerPubKeyB64 = await getRecipientPublicKey(token, recipientId);
    } else {
      peerId = message.author;
      peerPubKeyB64 = senderKeyId || await getRecipientPublicKey(token, message.author);
    }

    if (!peerPubKeyB64) {
      return "🔒 [Encrypted — missing key]";
    }

    const sharedSecret = await getOrDeriveSharedSecret(peerId, peerPubKeyB64);
    return await decrypt(message.encrypted_content, message.nonce, sharedSecret);
  } catch (err) {
    console.warn("[E2EE] Decryption failed:", err);
    return "🔒 [Unable to decrypt]";
  }
}

/**
 * Decrypt a ratchet-encrypted message.
 * If the sender is new, establishes a responder session via X3DH.
 */
async function decryptRatchetMessage(
  token: string,
  message: api.Message,
  header: RatchetHeader
): Promise<string> {
  const senderId = message.author;
  const senderDeviceId = header.deviceId;

  if (!ownDeviceId || !ownUserId) {
    return "🔒 [E2EE not initialized]";
  }

  // Check if we need to look at the deviceKeys for our specific device
  let ciphertext = message.encrypted_content!;
  let nonce = message.nonce!;
  let msgHeader = header;

  // If the message has deviceKeys and we're not the primary target,
  // find our device's ciphertext
  const fullHeader = JSON.parse(message.sender_key_id!) as RatchetHeader & {
    deviceKeys?: Record<string, { ciphertext: string; nonce: string; header: RatchetHeader }>;
  };
  if (fullHeader.deviceKeys?.[ownDeviceId]) {
    const devPayload = fullHeader.deviceKeys[ownDeviceId];
    ciphertext = devPayload.ciphertext;
    nonce = devPayload.nonce;
    msgHeader = devPayload.header;
  }

  // Try existing session
  let session = await getRatchetSession(senderId, senderDeviceId);

  if (!session) {
    // New sender — establish responder session via X3DH
    const stored = await getKeyPair(ownUserId);
    if (!stored) return "🔒 [No keypair]";

    const spk = await getLatestSignedPreKey();
    if (!spk) return "🔒 [No signed prekey]";

    const spkPrivate = await importPrivateJwkForX3DH(spk.privateKeyJwk);

    // Fetch sender's identity key
    const senderIdentityKeyB64 = await getRecipientPublicKey(token, senderId);
    if (!senderIdentityKeyB64) return "🔒 [Unknown sender]";

    // The ephemeral key from X3DH is the sender's ratchet key in the first message
    const sharedSecret = await x3dhResponder(
      stored.privateKey, spkPrivate, null,
      senderIdentityKeyB64, msgHeader.ratchetKey
    );

    session = await createResponderSession(
      sharedSecret, spk.privateKeyJwk, spk.publicKeyB64,
      ownDeviceId, senderId, senderDeviceId
    );
  }

  const plaintext = await ratchetDecrypt(session, ciphertext, nonce, msgHeader);
  await saveRatchetSession(senderId, senderDeviceId, session);
  return plaintext;
}

/** Import a JWK private key for X3DH ECDH */
async function importPrivateJwkForX3DH(jwk: JsonWebKey): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey("jwk", jwk, { name: "X25519" } as any, false, ["deriveBits"]);
  } catch {
    return await crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  }
}

// ── Group DM Encrypt ────────────────────────────────────────────

export interface GroupEncryptedPayload extends EncryptedPayload {
  /** Per-recipient wrapped message keys: userId → ratchet JSON or legacy "ct:nonce" */
  encryptedKeys: Record<string, string>;
}

/**
 * Encrypt a plaintext message for a Group DM with multiple recipients.
 *
 * Algorithm:
 * 1. Generate a random AES-256 per-message key
 * 2. Encrypt the plaintext with this message key
 * 3. For each recipient, wrap (encrypt) the raw message key using a
 *    ratchet session (forward secrecy). Falls back to static ECDH if
 *    no ratchet session can be established.
 * 4. Return ciphertext + wrapped keys map
 */
export async function encryptForGroupDm(
  token: string,
  plaintext: string,
  recipientIds: string[]
): Promise<GroupEncryptedPayload | null> {
  try {
    if (!ownPublicKeyB64 || !ownUserId || !ownDeviceId) {
      console.warn("[E2EE] Not initialized for group encryption");
      return null;
    }

    // 1. Generate a random AES-256-GCM key for this message
    const messageKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,  // extractable — we need to export & wrap it
      ["encrypt", "decrypt"]
    );

    // 2. Encrypt the plaintext with the message key
    const { ciphertext, nonce } = await encrypt(plaintext, messageKey);

    // 3. Export the raw message key bytes (for wrapping)
    const rawKeyBytes = await crypto.subtle.exportKey("raw", messageKey);
    const rawKeyB64 = btoa(String.fromCharCode(...new Uint8Array(rawKeyBytes)));

    // 4. Wrap the message key for each recipient via ratchet or legacy
    const encryptedKeys: Record<string, string> = {};

    for (const recipientId of recipientIds) {
      if (recipientId === ownUserId) continue; // skip self

      const wrapped = await wrapKeyForRecipient(token, recipientId, rawKeyB64);
      if (wrapped) {
        encryptedKeys[recipientId] = wrapped;
      }
    }

    // At least one recipient must have keys
    if (Object.keys(encryptedKeys).length === 0) {
      console.warn("[E2EE] No recipients with public keys, cannot encrypt for group");
      return null;
    }

    // senderKeyId = "ratchet-group" to distinguish from legacy and 1:1 ratchet
    return {
      ciphertext,
      nonce,
      senderKeyId: "ratchet-group",
      encryptedKeys,
    };
  } catch (err) {
    console.error("[E2EE] Group encryption failed:", err);
    return null;
  }
}

/**
 * Wrap a base64 key for a single recipient using their ratchet session.
 * Falls back to legacy static ECDH if no session can be established.
 * Returns the wrapped key string, or null on failure.
 *
 * Ratchet format: JSON `{"r": header, "c": ciphertext, "n": nonce}`
 * Legacy format: `ciphertext:nonce`
 */
async function wrapKeyForRecipient(
  token: string,
  recipientId: string,
  rawKeyB64: string
): Promise<string | null> {
  if (!ownUserId || !ownDeviceId) return null;

  // Try ratchet session first  
  let sessions = await getAllRatchetSessions(recipientId);

  if (sessions.length === 0) {
    // Attempt X3DH to establish a session
    try {
      const bundle = await api.users.claimPrekeys(token, recipientId);
      const stored = await getKeyPair(ownUserId);
      if (!stored) throw new Error("No keypair");

      for (const dev of bundle.devices) {
        const devBundle: X3DHDeviceBundle = {
          deviceId: dev.device_id,
          identityKeyB64: bundle.identity_key,
          signedPreKeyB64: dev.signed_prekey,
          signedPreKeySigB64: dev.signed_prekey_signature,
          oneTimePreKeyB64: dev.one_time_prekey,
        };
        const { sharedSecret } = await x3dhInitiator(stored.privateKey, devBundle);
        const session = await createInitiatorSession(
          sharedSecret, dev.signed_prekey, ownDeviceId, recipientId, dev.device_id
        );
        await saveRatchetSession(recipientId, dev.device_id, session);
      }
      sessions = await getAllRatchetSessions(recipientId);
    } catch (err) {
      devLog("[E2EE]", "X3DH failed for group recipient", recipientId, "falling back to legacy", err);
    }
  }

  // Use ratchet if we have a session
  if (sessions.length > 0) {
    try {
      const sess = sessions[0];
      const { ciphertext: wCt, nonce: wN, header } = await ratchetEncrypt(sess, rawKeyB64);
      await saveRatchetSession(recipientId, sess.peerDeviceId, sess);
      return JSON.stringify({ r: header, c: wCt, n: wN });
    } catch (err) {
      devLog("[E2EE]", "Ratchet wrap failed for", recipientId, err);
    }
  }

  // Legacy static ECDH fallback
  const recipientPubKeyB64 = await getRecipientPublicKey(token, recipientId);
  if (!recipientPubKeyB64) {
    console.warn(`[E2EE] Recipient ${recipientId} has no public key, skipping`);
    return null;
  }
  const pairwiseSecret = await getOrDeriveSharedSecret(recipientId, recipientPubKeyB64);
  const wrapped = await encrypt(rawKeyB64, pairwiseSecret);
  return `${wrapped.ciphertext}:${wrapped.nonce}`;
}

// ── Group DM Decrypt ────────────────────────────────────────────

/**
 * Decrypt a Group DM message that uses per-recipient wrapped keys.
 *
 * Detects whether each wrapped key was ratchet-wrapped (JSON `{r, c, n}`)
 * or legacy-wrapped (`ciphertext:nonce`), and unwraps accordingly.
 * The unwrapped per-message key is then used to decrypt the ciphertext.
 */
export async function decryptGroupDm(
  token: string,
  message: api.Message
): Promise<string> {
  if (!message.encrypted_content || !message.nonce || !message.encrypted_keys) {
    return message.content;
  }

  if (!ownUserId) {
    return "🔒 [E2EE not initialized]";
  }

  try {
    // 1. Find our wrapped key
    const wrappedEntry = message.encrypted_keys[ownUserId];
    if (!wrappedEntry) {
      return "🔒 [No key for this recipient]";
    }

    let rawKeyB64: string;

    // 2. Detect ratchet vs legacy wrapping
    if (wrappedEntry.startsWith("{")) {
      // Ratchet-wrapped: JSON {r: header, c: ciphertext, n: nonce}
      const parsed = JSON.parse(wrappedEntry);
      const senderId = message.author;
      const wrapHeader = parsed.r as RatchetHeader;
      const senderDeviceId = wrapHeader.deviceId;

      // Get or establish ratchet session with sender
      let session = await getRatchetSession(senderId, senderDeviceId);

      if (!session) {
        // New sender — establish responder session via X3DH
        // (mirrors the pattern in decryptRatchetMessage)
        const stored = await getKeyPair(ownUserId);
        if (!stored || !ownDeviceId) throw new Error("No keypair or device ID");

        const spk = await getLatestSignedPreKey();
        if (!spk) throw new Error("No signed prekey for responder session");

        const spkPrivate = await importPrivateJwkForX3DH(spk.privateKeyJwk);

        const senderIdentityKeyB64 = await getRecipientPublicKey(token, senderId);
        if (!senderIdentityKeyB64) throw new Error("Cannot get sender identity key");

        // ephemeral key from X3DH is the sender's ratchet key in the first message
        const sharedSecret = await x3dhResponder(
          stored.privateKey, spkPrivate, null,
          senderIdentityKeyB64, wrapHeader.ratchetKey
        );

        session = await createResponderSession(
          sharedSecret, spk.privateKeyJwk, spk.publicKeyB64,
          ownDeviceId, senderId, senderDeviceId
        );
      }

      rawKeyB64 = await ratchetDecrypt(session, parsed.c, parsed.n, wrapHeader);
      await saveRatchetSession(senderId, senderDeviceId, session);
    } else {
      // Legacy: "ciphertext:nonce" wrapped with static ECDH
      const senderPubKeyB64 = message.sender_key_id;
      if (!senderPubKeyB64) {
        return "🔒 [Missing sender key]";
      }
      const pairwiseSecret = await getOrDeriveSharedSecret(message.author, senderPubKeyB64);
      const [wrappedCiphertext, wrappedNonce] = wrappedEntry.split(":");
      rawKeyB64 = await decrypt(wrappedCiphertext, wrappedNonce, pairwiseSecret);
    }

    // 3. Import the message key
    const rawKeyBytes = Uint8Array.from(atob(rawKeyB64), c => c.charCodeAt(0));
    const messageKey = await crypto.subtle.importKey(
      "raw",
      rawKeyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    // 4. Decrypt the message
    const plaintext = await decrypt(message.encrypted_content, message.nonce, messageKey);
    return plaintext;
  } catch (err) {
    console.warn("[E2EE] Group decryption failed:", err);
    return "🔒 [Unable to decrypt]";
  }
}

// ── Utilities ───────────────────────────────────────────────────

/**
 * Check if E2EE has been initialized.
 */
export function isInitialized(): boolean {
  return ownPublicKeyB64 !== null && ownUserId !== null;
}

/**
 * Get our own public key (base64).
 */
export function getOwnPublicKey(): string | null {
  return ownPublicKeyB64;
}

/**
 * Clear all cached secrets (call on logout).
 */
export function clearE2EEState(): void {
  publicKeyCache.clear();
  sharedSecretCache.clear();
  ownPublicKeyB64 = null;
  ownUserId = null;
}

/**
 * Check if a message is end-to-end encrypted.
 */
export function isEncryptedMessage(message: api.Message): boolean {
  return !!message.encrypted_content && !!message.nonce;
}

/**
 * Check if a message uses Group DM E2EE (has per-recipient wrapped keys).
 */
export function isGroupEncryptedMessage(message: api.Message): boolean {
  return !!message.encrypted_content && !!message.nonce && !!message.encrypted_keys;
}

// ── File Encryption Helpers ─────────────────────────────────────

/**
 * Get the pairwise shared secret for a 1:1 DM recipient.
 * Returns null if keys aren't available.
 */
export async function getSharedSecretForDm(
  token: string,
  recipientId: string
): Promise<CryptoKey | null> {
  try {
    const recipientPubKeyB64 = await getRecipientPublicKey(token, recipientId);
    if (!recipientPubKeyB64) return null;
    return await getOrDeriveSharedSecret(recipientId, recipientPubKeyB64);
  } catch (err) {
    console.warn("[E2EE] Failed to derive shared secret for file:", err);
    return null;
  }
}

/**
 * Encrypt a file for a 1:1 DM. Returns FileEncryptionMeta or null.
 */
export async function encryptFileForDm(
  token: string,
  recipientId: string,
  file: File
): Promise<{ encryptedFile: File; meta: import("./api/media").FileEncryptionMeta } | null> {
  try {
    const { encryptFile, wrapFileKey } = await import("./fileCrypto");

    const sharedSecret = await getSharedSecretForDm(token, recipientId);
    if (!sharedSecret || !ownPublicKeyB64) return null;

    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const encrypted = await encryptFile(fileBytes);
    const wrapped = await wrapFileKey(encrypted.fileKey, sharedSecret);

    const encryptedBlob = new Blob([encrypted.ciphertext.buffer as ArrayBuffer], { type: "application/octet-stream" });
    const encryptedFile = new File([encryptedBlob], file.name, { type: "application/octet-stream" });

    return {
      encryptedFile,
      meta: {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        wrappedKey: wrapped.wrappedKey,
        wrapNonce: wrapped.wrapNonce,
        senderKeyId: ownPublicKeyB64,
        originalContentType: file.type || "application/octet-stream",
        originalFilename: file.name,
      },
    };
  } catch (err) {
    console.error("[E2EE] File encryption failed:", err);
    return null;
  }
}

/**
 * Encrypt a file for a Group DM with multiple recipients.
 * Wraps the per-file key for each recipient using ratchet sessions (forward secrecy),
 * with fallback to static ECDH.
 */
export async function encryptFileForGroupDm(
  token: string,
  recipientIds: string[],
  file: File
): Promise<{ encryptedFile: File; meta: import("./api/media").FileEncryptionMeta } | null> {
  try {
    const { encryptFile } = await import("./fileCrypto");

    if (!ownPublicKeyB64 || !ownUserId || !ownDeviceId) return null;

    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const encrypted = await encryptFile(fileBytes);

    // Export the raw file key to base64 so we can ratchet-wrap it like a message key
    const rawKeyBytes = await crypto.subtle.exportKey("raw", encrypted.fileKey);
    const rawKeyB64 = btoa(String.fromCharCode(...new Uint8Array(rawKeyBytes)));

    // Wrap the per-file key for each recipient via ratchet or legacy
    const wrappedKeys: Record<string, string> = {};

    for (const recipientId of recipientIds) {
      if (recipientId === ownUserId) continue;

      const wrapped = await wrapKeyForRecipient(token, recipientId, rawKeyB64);
      if (wrapped) {
        wrappedKeys[recipientId] = wrapped;
      }
    }

    if (Object.keys(wrappedKeys).length === 0) return null;

    const encryptedBlob = new Blob([encrypted.ciphertext.buffer as ArrayBuffer], { type: "application/octet-stream" });
    const encryptedFile = new File([encryptedBlob], file.name, { type: "application/octet-stream" });

    return {
      encryptedFile,
      meta: {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        wrappedKey: "",
        wrapNonce: "",
        senderKeyId: "ratchet-group",
        originalContentType: file.type || "application/octet-stream",
        originalFilename: file.name,
        wrappedKeys: JSON.stringify(wrappedKeys),
      },
    };
  } catch (err) {
    console.error("[E2EE] Group file encryption failed:", err);
    return null;
  }
}

/**
 * Encrypt a file for an MLS-enabled server channel.
 *
 * 1. Generates a random per-file AES-256-GCM key and encrypts the file.
 * 2. MLS-encrypts the file key + nonce as a JSON payload via the channel group.
 * 3. Returns the encrypted file (for upload) + the MLS message (for sending).
 *
 * The backend also applies server-managed encryption on top, so the storage
 * provider never sees either the plaintext OR the client-encrypted bytes.
 */
export async function encryptFileForMls(
  channelId: string,
  file: File
): Promise<{ encryptedFile: File; meta: import("./api/media").FileEncryptionMeta } | null> {
  try {
    const { encryptFile, uint8ToBase64 } = await import("./fileCrypto");
    const mls = await import("./mlsManager");

    if (!mls.isInitialized()) return null;

    const fileBytes = new Uint8Array(await file.arrayBuffer());
    const encrypted = await encryptFile(fileBytes);

    // Export the per-file key to base64 for MLS wrapping
    const rawKey = await crypto.subtle.exportKey("raw", encrypted.fileKey);
    const fileKeyB64 = uint8ToBase64(new Uint8Array(rawKey));

    // MLS-encrypt the file key + nonce as a JSON payload
    const keyPayload = JSON.stringify({
      type: "file_key",
      fileKey: fileKeyB64,
      nonce: encrypted.nonce,
      filename: file.name,
      contentType: file.type || "application/octet-stream",
    });

    const mlsWrapped = await mls.encryptForChannel(channelId, keyPayload);
    if (!mlsWrapped) return null;

    const encryptedBlob = new Blob([encrypted.ciphertext.buffer as ArrayBuffer], { type: "application/octet-stream" });
    const encryptedFile = new File([encryptedBlob], file.name, { type: "application/octet-stream" });

    return {
      encryptedFile,
      meta: {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        // MLS handles key distribution — no ECDH wrapping needed
        wrappedKey: "",
        wrapNonce: "",
        senderKeyId: "mls",
        originalContentType: file.type || "application/octet-stream",
        originalFilename: file.name,
        mlsMessage: mlsWrapped.mls_message,
        mlsEpoch: mlsWrapped.epoch,
      },
    };
  } catch (err) {
    console.error("[E2EE] MLS file encryption failed:", err);
    return null;
  }
}
