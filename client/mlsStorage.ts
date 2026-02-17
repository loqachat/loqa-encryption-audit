// MLS Storage — IndexedDB persistence for MLS group state
// Bridges the WASM in-memory state to persistent browser storage.

const DB_NAME = "loqa-mls";
const DB_VERSION = 1;
const STORE_GROUPS = "groups";
const STORE_IDENTITY = "identity";

interface MlsGroupRecord {
  channelId: string;
  epoch: number;
  lastUpdated: number;
}

interface MlsIdentityRecord {
  userId: string;
  initialized: boolean;
  keyPackageCount: number;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_GROUPS)) {
        db.createObjectStore(STORE_GROUPS, { keyPath: "channelId" });
      }
      if (!db.objectStoreNames.contains(STORE_IDENTITY)) {
        db.createObjectStore(STORE_IDENTITY, { keyPath: "userId" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function txPut<T>(db: IDBDatabase, store: string, data: T): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(data);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function txGet<T>(db: IDBDatabase, store: string, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

function txDelete(db: IDBDatabase, store: string, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ── Public API ────────────────────────────────────────────────

export async function saveGroupState(channelId: string, epoch: number): Promise<void> {
  const db = await openDB();
  await txPut<MlsGroupRecord>(db, STORE_GROUPS, {
    channelId,
    epoch,
    lastUpdated: Date.now(),
  });
  db.close();
}

export async function getGroupState(channelId: string): Promise<MlsGroupRecord | undefined> {
  const db = await openDB();
  const result = await txGet<MlsGroupRecord>(db, STORE_GROUPS, channelId);
  db.close();
  return result;
}

export async function removeGroupState(channelId: string): Promise<void> {
  const db = await openDB();
  await txDelete(db, STORE_GROUPS, channelId);
  db.close();
}

export async function saveIdentity(userId: string, keyPackageCount: number): Promise<void> {
  const db = await openDB();
  await txPut<MlsIdentityRecord>(db, STORE_IDENTITY, {
    userId,
    initialized: true,
    keyPackageCount,
  });
  db.close();
}

export async function getIdentity(userId: string): Promise<MlsIdentityRecord | undefined> {
  const db = await openDB();
  const result = await txGet<MlsIdentityRecord>(db, STORE_IDENTITY, userId);
  db.close();
  return result;
}

export async function clearAll(): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}
