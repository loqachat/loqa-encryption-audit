// IndexedDB-backed private key storage for E2EE
// Private keys never leave the device.

import type { RatchetSession } from "./doubleRatchet";

const DB_NAME = "loqa_e2ee";
const DB_VERSION = 2; // bumped for ratchet stores
const STORE_KEYPAIRS = "keypairs";
const STORE_RATCHET = "ratchet_sessions";
const STORE_SIGNED_PREKEYS = "signed_prekeys";
const STORE_OTP_PREKEYS = "otp_prekeys";
const STORE_DEVICE = "device_info";

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // v1: keypairs
      if (!db.objectStoreNames.contains(STORE_KEYPAIRS)) {
        db.createObjectStore(STORE_KEYPAIRS, { keyPath: "userId" });
      }
      // v2: ratchet sessions keyed by "peerId:peerDeviceId"
      if (!db.objectStoreNames.contains(STORE_RATCHET)) {
        db.createObjectStore(STORE_RATCHET, { keyPath: "sessionKey" });
      }
      // v2: signed prekey private keys (for responding to X3DH)
      if (!db.objectStoreNames.contains(STORE_SIGNED_PREKEYS)) {
        db.createObjectStore(STORE_SIGNED_PREKEYS, { keyPath: "id" });
      }
      // v2: one-time prekey private keys (JWK, indexed by public key b64)
      if (!db.objectStoreNames.contains(STORE_OTP_PREKEYS)) {
        db.createObjectStore(STORE_OTP_PREKEYS, { keyPath: "publicKeyB64" });
      }
      // v2: our device ID
      if (!db.objectStoreNames.contains(STORE_DEVICE)) {
        db.createObjectStore(STORE_DEVICE, { keyPath: "key" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export interface StoredKeyPair {
  userId: string;
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Save a keypair for a user. The private key stays in IndexedDB
 * (non-extractable) and never leaves the device.
 */
export async function saveKeyPair(
  userId: string,
  keyPair: CryptoKeyPair
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYPAIRS, "readwrite");
    tx.objectStore(STORE_KEYPAIRS).put({
      userId,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * Get the stored keypair for a user, or null if none exists.
 */
export async function getKeyPair(userId: string): Promise<StoredKeyPair | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYPAIRS, "readonly");
    const req = tx.objectStore(STORE_KEYPAIRS).get(userId);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Check if a keypair exists for a user.
 */
export async function hasKeyPair(userId: string): Promise<boolean> {
  const pair = await getKeyPair(userId);
  return pair !== null;
}

/**
 * Delete the stored keypair for a user.
 */
export async function deleteKeyPair(userId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_KEYPAIRS, "readwrite");
    tx.objectStore(STORE_KEYPAIRS).delete(userId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Ratchet Session Storage ─────────────────────────────────────

function sessionKey(peerId: string, peerDeviceId: string): string {
  return `${peerId}:${peerDeviceId}`;
}

/** Save or update a ratchet session for a (peer, device) pair */
export async function saveRatchetSession(
  peerId: string,
  peerDeviceId: string,
  session: RatchetSession
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RATCHET, "readwrite");
    tx.objectStore(STORE_RATCHET).put({
      sessionKey: sessionKey(peerId, peerDeviceId),
      ...session,
    });
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Get a ratchet session for a (peer, device) pair, or null */
export async function getRatchetSession(
  peerId: string,
  peerDeviceId: string
): Promise<RatchetSession | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RATCHET, "readonly");
    const req = tx.objectStore(STORE_RATCHET).get(sessionKey(peerId, peerDeviceId));
    req.onsuccess = () => {
      if (!req.result) return resolve(null);
      // Strip the sessionKey field and return pure RatchetSession
      const { sessionKey: _sk, ...session } = req.result;
      resolve(session as RatchetSession);
    };
    req.onerror = () => reject(req.error);
  });
}

/** Get all ratchet sessions for a peer (across all their devices) */
export async function getAllRatchetSessions(
  peerId: string
): Promise<RatchetSession[]> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RATCHET, "readonly");
    const store = tx.objectStore(STORE_RATCHET);
    const req = store.getAll();
    req.onsuccess = () => {
      const all = (req.result || [])
        .filter((r: any) => r.peerId === peerId)
        .map(({ sessionKey: _sk, ...s }: any) => s as RatchetSession);
      resolve(all);
    };
    req.onerror = () => reject(req.error);
  });
}

/** Delete a specific ratchet session */
export async function deleteRatchetSession(
  peerId: string,
  peerDeviceId: string
): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_RATCHET, "readwrite");
    tx.objectStore(STORE_RATCHET).delete(sessionKey(peerId, peerDeviceId));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Signed Prekey Storage ───────────────────────────────────────

export interface StoredSignedPreKey {
  id: string; // server-assigned ID
  publicKeyB64: string;
  privateKeyJwk: JsonWebKey;
  createdAt: number;
}

export async function saveSignedPreKey(spk: StoredSignedPreKey): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_SIGNED_PREKEYS, "readwrite");
    tx.objectStore(STORE_SIGNED_PREKEYS).put(spk);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getSignedPreKey(id: string): Promise<StoredSignedPreKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_SIGNED_PREKEYS, "readonly");
    const req = tx.objectStore(STORE_SIGNED_PREKEYS).get(id);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

/** Get the most recently stored signed prekey */
export async function getLatestSignedPreKey(): Promise<StoredSignedPreKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_SIGNED_PREKEYS, "readonly");
    const req = tx.objectStore(STORE_SIGNED_PREKEYS).getAll();
    req.onsuccess = () => {
      const all = req.result || [];
      if (all.length === 0) return resolve(null);
      all.sort((a: StoredSignedPreKey, b: StoredSignedPreKey) => b.createdAt - a.createdAt);
      resolve(all[0]);
    };
    req.onerror = () => reject(req.error);
  });
}

// ── One-Time Prekey Storage ─────────────────────────────────────

export interface StoredOTPPreKey {
  publicKeyB64: string;
  privateKeyJwk: JsonWebKey;
}

export async function saveOTPPreKeys(keys: StoredOTPPreKey[]): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OTP_PREKEYS, "readwrite");
    const store = tx.objectStore(STORE_OTP_PREKEYS);
    for (const k of keys) {
      store.put(k);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getOTPPreKey(publicKeyB64: string): Promise<StoredOTPPreKey | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OTP_PREKEYS, "readonly");
    const req = tx.objectStore(STORE_OTP_PREKEYS).get(publicKeyB64);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  });
}

export async function deleteOTPPreKey(publicKeyB64: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_OTP_PREKEYS, "readwrite");
    tx.objectStore(STORE_OTP_PREKEYS).delete(publicKeyB64);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Device ID Storage ───────────────────────────────────────────

/** Get or generate a persistent device ID for this browser */
export async function getOrCreateDeviceId(): Promise<string> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_DEVICE, "readwrite");
    const store = tx.objectStore(STORE_DEVICE);
    const req = store.get("deviceId");
    req.onsuccess = () => {
      if (req.result?.value) {
        resolve(req.result.value);
      } else {
        // Generate a new device ID
        const deviceId = crypto.randomUUID();
        store.put({ key: "deviceId", value: deviceId });
        tx.oncomplete = () => resolve(deviceId);
      }
    };
    req.onerror = () => reject(req.error);
  });
}
