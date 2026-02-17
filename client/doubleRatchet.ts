/**
 * Double Ratchet protocol for 1:1 DMs (Olm/Signal-style)
 *
 * Implements:
 * 1. X3DH key agreement (session establishment)
 * 2. Symmetric ratchet (per-message key derivation)
 * 3. DH ratchet (periodic key rotation on reply)
 *
 * Multi-device: sessions are keyed by (peerId, deviceId).
 * Uses Web Crypto API exclusively — no external dependencies.
 */

import { generateKeyPair, exportPublicKey, importPublicKey } from "./crypto";
import { devLog } from "./logger";

// ── Types ────────────────────────────────────────────────────────

/** Header sent alongside every ratchet-encrypted message */
export interface RatchetHeader {
  /** Sender's current ratchet public key (base64) */
  ratchetKey: string;
  /** Message counter within the current sending chain */
  counter: number;
  /** Number of messages in the previous sending chain (for skipped key calc) */
  previousCounter: number;
  /** Sender's device ID */
  deviceId: string;
}

/** Serializable session state — persisted in IndexedDB per (peerId, deviceId) */
export interface RatchetSession {
  /** Root key (32 bytes, base64) */
  rootKey: string;
  /** Sending chain key (32 bytes, base64) — null until we've sent at least once */
  sendChainKey: string | null;
  /** Receiving chain key (32 bytes, base64) — null until we've received */
  recvChainKey: string | null;
  /** Our current ratchet key pair (JWK format for serialization) */
  myRatchetKeyJwk: JsonWebKey;
  myRatchetKeyPublicB64: string;
  /** Their current ratchet public key (base64) — null for initiator before first reply */
  theirRatchetKeyB64: string | null;
  /** Send/receive counters */
  sendCount: number;
  recvCount: number;
  /** Previous chain length (for header) */
  prevChainLength: number;
  /** Skipped message keys: Map<"ratchetPubB64:counter", base64-messageKey> */
  skippedKeys: Record<string, string>;
  /** Peer user ID */
  peerId: string;
  /** Peer device ID */
  peerDeviceId: string;
  /** Our device ID */
  ourDeviceId: string;
  /** Session established timestamp */
  createdAt: number;
}

/** Bundle for one device from the server (matches DeviceBundle in api) */
export interface X3DHDeviceBundle {
  deviceId: string;
  identityKeyB64: string;
  signedPreKeyB64: string;
  signedPreKeySigB64: string;
  oneTimePreKeyB64?: string;
}

// ── Constants ────────────────────────────────────────────────────

const MAX_SKIP = 256; // max skipped message keys to store
const INFO_ROOT = new TextEncoder().encode("loqa-dr-root");
const INFO_CHAIN = new TextEncoder().encode("loqa-dr-chain");
const INFO_MSG = new TextEncoder().encode("loqa-dr-msg");
const INFO_X3DH = new TextEncoder().encode("loqa-x3dh");

// ── Utility: base64 encoding/decoding ───────────────────────────

export function b64Encode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function b64Decode(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ── Low-level crypto primitives ─────────────────────────────────

/** ECDH deriveBits using X25519 (or P-256 fallback) */
async function ecdhDeriveBits(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  const algo = (privateKey.algorithm as any).name || "X25519";
  return crypto.subtle.deriveBits(
    { name: algo, public: publicKey } as any,
    privateKey,
    256
  );
}

/** HKDF-SHA256: derive `length` bytes from input key material */
async function hkdfDerive(
  ikm: ArrayBuffer,
  salt: ArrayBuffer,
  info: Uint8Array,
  length: number
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    "deriveBits",
  ]);
  return crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(salt) as BufferSource, info: info as BufferSource },
    key,
    length * 8
  );
}

/** KDF for ratchet: takes root key + DH output → new root key + chain key */
async function kdfRootKey(
  rootKey: ArrayBuffer,
  dhOutput: ArrayBuffer
): Promise<{ newRootKey: ArrayBuffer; chainKey: ArrayBuffer }> {
  const derived = await hkdfDerive(dhOutput, rootKey, INFO_ROOT, 64);
  return {
    newRootKey: derived.slice(0, 32),
    chainKey: derived.slice(32, 64),
  };
}

/** KDF for chain: advance chain key → new chain key + message key */
async function kdfChainKey(
  chainKey: ArrayBuffer
): Promise<{ newChainKey: ArrayBuffer; messageKey: ArrayBuffer }> {
  // Chain key derivation uses HMAC-like pattern via HKDF
  const msgKeyMaterial = await hkdfDerive(
    chainKey,
    new ArrayBuffer(32),
    INFO_MSG,
    32
  );
  const newChainMaterial = await hkdfDerive(
    chainKey,
    new ArrayBuffer(32),
    INFO_CHAIN,
    32
  );
  return {
    newChainKey: newChainMaterial,
    messageKey: msgKeyMaterial,
  };
}

/** Import raw bytes as an AES-GCM key for encrypt/decrypt */
async function importMessageKey(raw: ArrayBuffer): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Export a CryptoKey (private) to JWK for serialization */
async function exportKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", key);
}

/** Import a JWK private key for ECDH */
async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey("jwk", jwk, { name: "X25519" } as any, true, [
      "deriveBits",
    ]);
  } catch {
    return await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  }
}

/** Generate a fresh ratchet key pair (extractable for JWK serialization) */
async function generateRatchetKeyPair(): Promise<CryptoKeyPair> {
  try {
    return await crypto.subtle.generateKey({ name: "X25519" } as any, true, [
      "deriveBits",
    ]);
  } catch {
    return await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  }
}

// ── X3DH Key Agreement ──────────────────────────────────────────

/**
 * Initiator side of X3DH.
 * Returns the shared secret and ephemeral key (for the header).
 */
export async function x3dhInitiator(
  ourIdentityPrivateKey: CryptoKey,
  theirBundle: X3DHDeviceBundle
): Promise<{ sharedSecret: ArrayBuffer; ephemeralKeyB64: string }> {
  const theirIdentityKey = await importPublicKey(theirBundle.identityKeyB64);
  const theirSignedPreKey = await importPublicKey(theirBundle.signedPreKeyB64);

  // Generate ephemeral key for this session
  const ephemeralKP = await generateRatchetKeyPair();
  const ephemeralPubB64 = await exportPublicKey(ephemeralKP.publicKey);

  // DH1 = ECDH(IK_A, SPK_B)
  const dh1 = await ecdhDeriveBits(ourIdentityPrivateKey, theirSignedPreKey);
  // DH2 = ECDH(EK_A, IK_B)
  const dh2 = await ecdhDeriveBits(ephemeralKP.privateKey, theirIdentityKey);
  // DH3 = ECDH(EK_A, SPK_B)
  const dh3 = await ecdhDeriveBits(ephemeralKP.privateKey, theirSignedPreKey);

  // Concatenate: DH1 || DH2 || DH3 [|| DH4]
  let totalLen = 32 * 3;
  let dh4: ArrayBuffer | null = null;

  if (theirBundle.oneTimePreKeyB64) {
    const theirOTPK = await importPublicKey(theirBundle.oneTimePreKeyB64);
    dh4 = await ecdhDeriveBits(ephemeralKP.privateKey, theirOTPK);
    totalLen += 32;
  }

  const concat = new Uint8Array(totalLen);
  concat.set(new Uint8Array(dh1), 0);
  concat.set(new Uint8Array(dh2), 32);
  concat.set(new Uint8Array(dh3), 64);
  if (dh4) concat.set(new Uint8Array(dh4), 96);

  // Derive shared secret via HKDF
  const sharedSecret = await hkdfDerive(
    concat.buffer as ArrayBuffer,
    new ArrayBuffer(32), // zero salt
    INFO_X3DH,
    32
  );

  return { sharedSecret, ephemeralKeyB64: ephemeralPubB64 };
}

/**
 * Responder side of X3DH.
 * Called when receiving the first message from a new peer.
 */
export async function x3dhResponder(
  ourIdentityPrivateKey: CryptoKey,
  ourSignedPreKeyPrivate: CryptoKey,
  ourOneTimePreKeyPrivate: CryptoKey | null,
  theirIdentityKeyB64: string,
  theirEphemeralKeyB64: string
): Promise<ArrayBuffer> {
  const theirIdentityKey = await importPublicKey(theirIdentityKeyB64);
  const theirEphemeralKey = await importPublicKey(theirEphemeralKeyB64);

  // DH1 = ECDH(SPK_B, IK_A) — mirror of initiator's DH1
  const dh1 = await ecdhDeriveBits(ourSignedPreKeyPrivate, theirIdentityKey);
  // DH2 = ECDH(IK_B, EK_A) — mirror of initiator's DH2
  const dh2 = await ecdhDeriveBits(ourIdentityPrivateKey, theirEphemeralKey);
  // DH3 = ECDH(SPK_B, EK_A) — mirror of initiator's DH3
  const dh3 = await ecdhDeriveBits(ourSignedPreKeyPrivate, theirEphemeralKey);

  let totalLen = 32 * 3;
  let dh4: ArrayBuffer | null = null;

  if (ourOneTimePreKeyPrivate) {
    dh4 = await ecdhDeriveBits(ourOneTimePreKeyPrivate, theirEphemeralKey);
    totalLen += 32;
  }

  const concat = new Uint8Array(totalLen);
  concat.set(new Uint8Array(dh1), 0);
  concat.set(new Uint8Array(dh2), 32);
  concat.set(new Uint8Array(dh3), 64);
  if (dh4) concat.set(new Uint8Array(dh4), 96);

  return hkdfDerive(concat.buffer as ArrayBuffer, new ArrayBuffer(32), INFO_X3DH, 32);
}

// ── Session Initialization ──────────────────────────────────────

/**
 * Create a new ratchet session as the INITIATOR (the one sending the first message).
 * The initiator knows the recipient's ratchet key (= their signed prekey).
 */
export async function createInitiatorSession(
  sharedSecret: ArrayBuffer,
  theirRatchetKeyB64: string, // = their signed prekey
  ourDeviceId: string,
  peerId: string,
  peerDeviceId: string
): Promise<RatchetSession> {
  const theirRatchetKey = await importPublicKey(theirRatchetKeyB64);

  // Generate our first ratchet key pair
  const myRatchetKP = await generateRatchetKeyPair();
  const myRatchetPubB64 = await exportPublicKey(myRatchetKP.publicKey);

  // Perform initial DH ratchet step
  const dhOutput = await ecdhDeriveBits(myRatchetKP.privateKey, theirRatchetKey);
  const { newRootKey, chainKey } = await kdfRootKey(sharedSecret, dhOutput);

  const myJwk = await exportKeyJwk(myRatchetKP.privateKey);

  return {
    rootKey: b64Encode(newRootKey),
    sendChainKey: b64Encode(chainKey),
    recvChainKey: null, // will be set when we receive the first reply
    myRatchetKeyJwk: myJwk,
    myRatchetKeyPublicB64: myRatchetPubB64,
    theirRatchetKeyB64,
    sendCount: 0,
    recvCount: 0,
    prevChainLength: 0,
    skippedKeys: {},
    peerId,
    peerDeviceId,
    ourDeviceId,
    createdAt: Date.now(),
  };
}

/**
 * Create a new ratchet session as the RESPONDER (receiving the first message).
 * The responder's signed prekey was used as the initial ratchet key.
 */
export async function createResponderSession(
  sharedSecret: ArrayBuffer,
  ourSignedPreKeyPrivateJwk: JsonWebKey,
  ourSignedPreKeyPublicB64: string,
  ourDeviceId: string,
  peerId: string,
  peerDeviceId: string
): Promise<RatchetSession> {
  return {
    rootKey: b64Encode(sharedSecret),
    sendChainKey: null,
    recvChainKey: null,
    myRatchetKeyJwk: ourSignedPreKeyPrivateJwk,
    myRatchetKeyPublicB64: ourSignedPreKeyPublicB64,
    theirRatchetKeyB64: null,
    sendCount: 0,
    recvCount: 0,
    prevChainLength: 0,
    skippedKeys: {},
    peerId,
    peerDeviceId,
    ourDeviceId,
    createdAt: Date.now(),
  };
}

// ── Ratchet Encrypt ─────────────────────────────────────────────

/**
 * Encrypt a plaintext message using the ratchet session.
 * Mutates the session state (advancing the sending chain).
 * Returns the ciphertext, nonce, and header.
 */
export async function ratchetEncrypt(
  session: RatchetSession,
  plaintext: string
): Promise<{ ciphertext: string; nonce: string; header: RatchetHeader }> {
  if (!session.sendChainKey) {
    throw new Error("Session has no sending chain — must receive first");
  }

  // Advance chain: derive message key + new chain key
  const ck = b64Decode(session.sendChainKey).buffer as ArrayBuffer;
  const { newChainKey, messageKey } = await kdfChainKey(ck);

  // Build header
  const header: RatchetHeader = {
    ratchetKey: session.myRatchetKeyPublicB64,
    counter: session.sendCount,
    previousCounter: session.prevChainLength,
    deviceId: session.ourDeviceId,
  };

  // Encrypt with AES-256-GCM
  const aesKey = await importMessageKey(messageKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    encoded
  );

  // Update session state
  session.sendChainKey = b64Encode(newChainKey);
  session.sendCount++;

  return {
    ciphertext: b64Encode(encrypted),
    nonce: b64Encode(iv.buffer as ArrayBuffer),
    header,
  };
}

// ── Ratchet Decrypt ─────────────────────────────────────────────

/**
 * Decrypt a message using the ratchet session.
 * Handles DH ratchet steps and skipped message keys.
 * Mutates the session state.
 */
export async function ratchetDecrypt(
  session: RatchetSession,
  ciphertext: string,
  nonce: string,
  header: RatchetHeader
): Promise<string> {
  // 1. Check skipped keys first
  const skipKey = `${header.ratchetKey}:${header.counter}`;
  if (session.skippedKeys[skipKey]) {
    const mk = b64Decode(session.skippedKeys[skipKey]).buffer as ArrayBuffer;
    delete session.skippedKeys[skipKey];
    return decryptWithKey(ciphertext, nonce, mk);
  }

  // 2. If their ratchet key changed, perform DH ratchet step
  if (header.ratchetKey !== session.theirRatchetKeyB64) {
    // Skip any remaining messages from the old chain
    if (session.recvChainKey !== null) {
      await skipMessageKeys(session, header.previousCounter);
    }

    // DH ratchet step
    await dhRatchetStep(session, header.ratchetKey);
  }

  // 3. Skip to the correct position in the current receiving chain
  await skipMessageKeys(session, header.counter);

  // 4. Derive the message key
  if (!session.recvChainKey) {
    throw new Error("No receiving chain key");
  }
  const ck = b64Decode(session.recvChainKey).buffer as ArrayBuffer;
  const { newChainKey, messageKey } = await kdfChainKey(ck);

  session.recvChainKey = b64Encode(newChainKey);
  session.recvCount++;

  return decryptWithKey(ciphertext, nonce, messageKey);
}

/** Decrypt ciphertext with a raw message key */
async function decryptWithKey(
  ciphertext: string,
  nonce: string,
  messageKey: ArrayBuffer
): Promise<string> {
  const aesKey = await importMessageKey(messageKey);
  const iv = b64Decode(nonce);
  const data = b64Decode(ciphertext);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    aesKey,
    data as BufferSource
  );

  return new TextDecoder().decode(decrypted);
}

/** Skip message keys up to `until` counter, caching them for out-of-order delivery */
async function skipMessageKeys(
  session: RatchetSession,
  until: number
): Promise<void> {
  if (!session.recvChainKey) return;
  if (session.recvCount > until) return;

  if (until - session.recvCount > MAX_SKIP) {
    throw new Error("Too many skipped messages");
  }

  let ck = b64Decode(session.recvChainKey).buffer as ArrayBuffer;

  while (session.recvCount < until) {
    const { newChainKey, messageKey } = await kdfChainKey(ck);
    const skipKey = `${session.theirRatchetKeyB64}:${session.recvCount}`;
    session.skippedKeys[skipKey] = b64Encode(messageKey);
    ck = newChainKey;
    session.recvCount++;
  }

  session.recvChainKey = b64Encode(ck as ArrayBuffer);
}

/** Perform a DH ratchet step when the peer's ratchet key changes */
async function dhRatchetStep(
  session: RatchetSession,
  newTheirRatchetKeyB64: string
): Promise<void> {
  session.prevChainLength = session.sendCount;
  session.sendCount = 0;
  session.recvCount = 0;
  session.theirRatchetKeyB64 = newTheirRatchetKeyB64;

  const theirNewKey = await importPublicKey(newTheirRatchetKeyB64);
  const myPrivate = await importPrivateJwk(session.myRatchetKeyJwk);

  // DH with our current ratchet private + their new public → new recv chain
  const dhOutput = await ecdhDeriveBits(myPrivate, theirNewKey);
  const rootKey = b64Decode(session.rootKey).buffer as ArrayBuffer;
  const { newRootKey, chainKey } = await kdfRootKey(rootKey, dhOutput);

  session.rootKey = b64Encode(newRootKey);
  session.recvChainKey = b64Encode(chainKey);

  // Generate new ratchet key pair for sending
  const newKP = await generateRatchetKeyPair();
  session.myRatchetKeyPublicB64 = await exportPublicKey(newKP.publicKey);
  session.myRatchetKeyJwk = await exportKeyJwk(newKP.privateKey);

  // DH with our new ratchet private + their new public → new send chain
  const dh2 = await ecdhDeriveBits(newKP.privateKey, theirNewKey);
  const { newRootKey: rk2, chainKey: ck2 } = await kdfRootKey(newRootKey, dh2);

  session.rootKey = b64Encode(rk2);
  session.sendChainKey = b64Encode(ck2);

  devLog("[DR]", "DH ratchet step complete, new ratchet key:", session.myRatchetKeyPublicB64.slice(0, 12) + "...");
}

// ── Prekey Generation Helpers ───────────────────────────────────

/**
 * Generate a signed prekey pair.
 * The public key is signed by the identity key to prove authenticity.
 */
export async function generateSignedPreKey(
  identityPrivateKey: CryptoKey
): Promise<{
  keyPair: CryptoKeyPair;
  publicKeyB64: string;
  privateKeyJwk: JsonWebKey;
  signatureB64: string;
}> {
  const keyPair = await generateRatchetKeyPair();
  const publicKeyB64 = await exportPublicKey(keyPair.publicKey);

  // Sign the public key bytes using a key derived from our identity key.
  // We derive a signing key via ECDH(identity_priv, prekey_pub) so that
  // only the holder of the identity private key can produce the signature,
  // and the verifier can reproduce it via ECDH(prekey_priv, identity_pub).
  const dhSigningMaterial = await ecdhDeriveBits(identityPrivateKey, keyPair.publicKey);
  const sigKey = await crypto.subtle.importKey(
    "raw",
    dhSigningMaterial,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const pubBytes = b64Decode(publicKeyB64);
  const signature = await crypto.subtle.sign("HMAC", sigKey, pubBytes as BufferSource);
  const signatureB64 = b64Encode(signature);

  const privateKeyJwk = await exportKeyJwk(keyPair.privateKey);

  return { keyPair, publicKeyB64, privateKeyJwk, signatureB64 };
}

/**
 * Generate a batch of one-time prekeys.
 * Returns public keys (for upload) and private JWKs (for local storage).
 */
export async function generateOneTimePreKeys(
  count: number
): Promise<{ publicKeysB64: string[]; privateJwks: JsonWebKey[] }> {
  const publicKeysB64: string[] = [];
  const privateJwks: JsonWebKey[] = [];

  for (let i = 0; i < count; i++) {
    const kp = await generateRatchetKeyPair();
    publicKeysB64.push(await exportPublicKey(kp.publicKey));
    privateJwks.push(await exportKeyJwk(kp.privateKey));
  }

  return { publicKeysB64, privateJwks };
}

// ── Header serialization ────────────────────────────────────────

/** Serialize a RatchetHeader to a string for the sender_key_id field */
export function serializeHeader(header: RatchetHeader): string {
  return JSON.stringify(header);
}

/** Try to parse a sender_key_id as a RatchetHeader. Returns null if it's a legacy identity key. */
export function parseHeader(senderKeyId: string): RatchetHeader | null {
  if (!senderKeyId.startsWith("{")) return null; // legacy base64 identity key
  try {
    const obj = JSON.parse(senderKeyId);
    if (obj.ratchetKey && typeof obj.counter === "number") {
      return obj as RatchetHeader;
    }
  } catch {
    // not JSON = legacy
  }
  return null;
}
