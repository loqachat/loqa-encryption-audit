// MLS Manager — high-level API for server-scale E2EE
// Wraps the OpenMLS WASM module and coordinates with the Delivery Service.
//
// Usage pattern mirrors e2eeManager.ts:
//   1. initMls(token, userId)          — on login
//   2. ensureGroupJoined(channelId)    — on channel open
//   3. encryptForChannel(channelId, text) — on send
//   4. decryptChannelMessage(channelId, mlsMsgB64) — on receive

import * as api from "./api";
import * as mlsStore from "./mlsStorage";
import { devLog } from "./logger";

// ── WASM Module ─────────────────────────────────────────────────
// The WASM module is loaded lazily on first use.

let wasmModule: any = null;
let mlsInitialized = false;
let currentUserId: string | null = null;
let currentToken: string | null = null;

// Minimum KeyPackages to maintain on the server
const MIN_KEY_PACKAGES = 10;
const KEY_PACKAGE_BATCH_SIZE = 20;

async function loadWasm(): Promise<any | null> {
  if (wasmModule) return wasmModule;
  try {
    // The WASM module is built by wasm-pack and placed in public/mls/.
    // Vite blocks import() of /public files, so we fetch the JS glue
    // code as text and create a blob URL to bypass Vite's module pipeline.
    const jsResponse = await fetch("/mls/loqa_mls_wasm.js");
    if (!jsResponse.ok) return null;
    const jsText = await jsResponse.text();
    const blob = new Blob([jsText], { type: "text/javascript" });
    const blobUrl = URL.createObjectURL(blob);
    wasmModule = await import(/* @vite-ignore */ blobUrl);
    URL.revokeObjectURL(blobUrl);

    // Pass the explicit WASM binary path so the init function doesn't
    // rely on import.meta.url (which would point to the blob URL).
    await wasmModule.default("/mls/loqa_mls_wasm_bg.wasm");
    return wasmModule;
  } catch {
    // WASM module not built yet — MLS E2EE is a planned feature
    return null;
  }
}

/** @internal — allows tests to inject a mock WASM module */
export function _injectWasmForTest(mock: any): void {
  wasmModule = mock;
}

// ── Initialization ──────────────────────────────────────────────

/**
 * Initialize MLS on login. Creates identity, generates KeyPackages,
 * and uploads them to the Delivery Service.
 */
export async function initMls(token: string, userId: string): Promise<void> {
  if (mlsInitialized && currentUserId === userId) return;

  currentToken = token;
  currentUserId = userId;

  try {
    const wasm = await loadWasm();
    if (!wasm) return; // WASM not available — MLS not active
    wasm.mls_init(userId);

    // Check if we have enough KeyPackages on the server
    await replenishKeyPackages(token);

    mlsInitialized = true;
    await mlsStore.saveIdentity(userId, MIN_KEY_PACKAGES);
    devLog("[MLS]", "Initialized for user", userId);
  } catch (err) {
    console.warn("[MLS] Init skipped:", err);
    mlsInitialized = false;
  }
}

/**
 * Ensure the server has enough KeyPackages for this user.
 */
async function replenishKeyPackages(token: string): Promise<void> {
  try {
    const { count } = await api.request<{ count: number }>(
      "GET", "/mls/key-packages/count", undefined, token
    );

    if (count < MIN_KEY_PACKAGES) {
      const wasm = await loadWasm();
      const needed = KEY_PACKAGE_BATCH_SIZE - count;
      const packages = wasm.mls_generate_key_packages(needed);
      const keyPackagesB64 = packages.map((p: any) => p.key_package_b64);

      await api.request("POST", "/mls/key-packages", {
        key_packages: keyPackagesB64,
        ciphersuite: 1,
      }, token);

      devLog("[MLS]", `Uploaded ${needed} KeyPackages`);
    }
  } catch (err) {
    console.warn("[MLS] KeyPackage replenish failed:", err);
  }
}

// ── Group Management ────────────────────────────────────────────

/**
 * Ensure the user has joined the MLS group for a channel.
 * Creates the group if it doesn't exist, or joins via Welcome.
 */
export async function ensureGroupJoined(channelId: string): Promise<boolean> {
  if (!mlsInitialized || !currentToken) return false;

  const wasm = await loadWasm();

  // Already in group?
  if (wasm.mls_has_group(channelId)) return true;

  try {
    // Check if a group exists on the server
    const groupState = await api.request<{
      channel_id: string;
      group_id: string;
      epoch: number;
      ratchet_tree?: string;
    }>("GET", `/mls/groups/${channelId}/state`, undefined, currentToken).catch(() => null);

    if (!groupState) {
      // No group yet — create one (we're the first E2EE member)
      const result = wasm.mls_create_group(channelId);
      await api.request("POST", `/mls/groups/${channelId}`, {
        group_id: result.group_id_b64,
        ratchet_tree: result.ratchet_tree_b64,
      }, currentToken);

      await mlsStore.saveGroupState(channelId, 0);
      devLog("[MLS]", "Created group for channel", channelId);
      return true;
    }

    // Group exists — check for a Welcome
    const welcomes = await api.request<Array<{
      id: string;
      channel_id: string;
      welcome: string;
    }>>("GET", "/mls/welcomes", undefined, currentToken);

    const welcome = welcomes.find(w => w.channel_id === channelId);
    if (welcome) {
      wasm.mls_join_group(channelId, welcome.welcome);
      // Ack the welcome
      await api.request("POST", `/mls/welcomes/${welcome.id}`, {}, currentToken);
      await mlsStore.saveGroupState(channelId, groupState.epoch);
      devLog("[MLS]", "Joined group via Welcome for channel", channelId);
      return true;
    }

    // No welcome yet — we need to be added by an existing member
    devLog("[MLS]", "Waiting to be added to group for channel", channelId);
    return false;
  } catch (err) {
    console.error("[MLS] ensureGroupJoined failed:", err);
    return false;
  }
}

/**
 * Add a member to a channel's MLS group.
 * Called when a new member joins the server or gains channel access.
 */
export async function addMemberToGroup(
  channelId: string,
  userId: string
): Promise<boolean> {
  if (!mlsInitialized || !currentToken) return false;

  const wasm = await loadWasm();
  if (!wasm.mls_has_group(channelId)) return false;

  try {
    // Claim a KeyPackage for the user
    const { key_package } = await api.request<{ key_package: string }>(
      "GET", `/mls/key-packages/${userId}`, undefined, currentToken
    );

    // Add them to the local group
    const result = wasm.mls_add_member(channelId, key_package);

    // Upload Commit + Welcome to the Delivery Service
    await api.request("POST", `/mls/groups/${channelId}/commit`, {
      commit: result.commit_b64,
      epoch: result.epoch,
      ratchet_tree: result.ratchet_tree_b64,
      welcomes: [{ user_id: userId, welcome: result.welcome_b64 }],
    }, currentToken);

    await mlsStore.saveGroupState(channelId, result.epoch);
    devLog("[MLS]", "Added member", userId, "to channel", channelId);
    return true;
  } catch (err) {
    console.error("[MLS] addMemberToGroup failed:", err);
    return false;
  }
}

// ── Encryption / Decryption ─────────────────────────────────────

/**
 * Encrypt a plaintext message for a channel's MLS group.
 * Returns the MLS message payload for the API.
 */
export async function encryptForChannel(
  channelId: string,
  plaintext: string
): Promise<{ mls_message: string; epoch: number } | null> {
  if (!mlsInitialized) return null;

  try {
    const wasm = await loadWasm();
    if (!wasm.mls_has_group(channelId)) {
      console.warn("[MLS] Not in group for channel", channelId);
      return null;
    }

    const result = wasm.mls_encrypt(channelId, plaintext);
    return {
      mls_message: result.mls_message_b64,
      epoch: result.epoch,
    };
  } catch (err) {
    console.error("[MLS] Encryption failed:", err);
    return null;
  }
}

/**
 * Decrypt an MLS application message.
 */
export async function decryptChannelMessage(
  channelId: string,
  mlsMessageB64: string
): Promise<string> {
  if (!mlsInitialized) return "🔒 [MLS not initialized]";

  try {
    const wasm = await loadWasm();
    if (!wasm.mls_has_group(channelId)) {
      return "🔒 [Not in E2EE group]";
    }

    const result = wasm.mls_decrypt(channelId, mlsMessageB64);
    return result.plaintext || "";
  } catch (err) {
    console.warn("[MLS] Decryption failed:", err);
    return "🔒 [Unable to decrypt]";
  }
}

/**
 * Process a Commit from another member (e.g., when they add/remove someone).
 */
export async function processCommit(
  channelId: string,
  commitB64: string
): Promise<void> {
  if (!mlsInitialized) return;

  try {
    const wasm = await loadWasm();
    if (!wasm.mls_has_group(channelId)) return;

    wasm.mls_process_commit(channelId, commitB64);
    const epoch = wasm.mls_group_epoch(channelId);
    await mlsStore.saveGroupState(channelId, epoch);
  } catch (err) {
    console.error("[MLS] Process commit failed:", err);
  }
}

// ── Query Functions ─────────────────────────────────────────────

export function isInitialized(): boolean {
  return mlsInitialized;
}

export async function hasGroup(channelId: string): Promise<boolean> {
  if (!mlsInitialized) return false;
  try {
    const wasm = await loadWasm();
    return wasm.mls_has_group(channelId);
  } catch {
    return false;
  }
}

/**
 * Fetch an MLS message's ciphertext from the Delivery Service by ID.
 */
export async function fetchMlsMessage(
  mlsMessageId: string,
  channelId: string
): Promise<string | null> {
  if (!currentToken) return null;
  try {
    const messages = await api.request<Array<{
      id: string;
      mls_message: string;
    }>>("GET", `/mls/groups/${channelId}/messages?limit=50`, undefined, currentToken);

    const msg = messages.find(m => m.id === mlsMessageId);
    return msg?.mls_message ?? null;
  } catch {
    return null;
  }
}

/**
 * Clear MLS state (e.g., on logout).
 */
export function clearMlsState(): void {
  mlsInitialized = false;
  currentUserId = null;
  currentToken = null;
  wasmModule = null;
  mlsStore.clearAll().catch(() => {});
}
