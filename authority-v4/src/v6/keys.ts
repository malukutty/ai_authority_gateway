import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { V6ApiKeyRecord, Visibility } from "./types.js";

const V6_KEYS_PATH = process.env.AUTHORITY_V6_KEYS_PATH || "./authority-v6.keys.json";

type StoredKeyRecord = V6ApiKeyRecord & {
  token: string;
};

function resolvePath() {
  return path.resolve(V6_KEYS_PATH);
}

function readKeys(): StoredKeyRecord[] {
  const filePath = resolvePath();
  if (!fs.existsSync(filePath)) return [];
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8")) as StoredKeyRecord[];
  } catch {
    return [];
  }
}

function writeKeys(keys: StoredKeyRecord[]) {
  fs.writeFileSync(resolvePath(), JSON.stringify(keys, null, 2), "utf8");
}

export function lookupV6ApiKey(rawToken: string): V6ApiKeyRecord | null {
  const match = readKeys().find((k) => k.token === rawToken && k.isActive);
  if (!match) return null;

  const { token: _token, ...safe } = match;
  return safe;
}

export function createV6ApiKey(params: {
  userId: string;
  visibility?: Visibility;
  dailySpendLimitUsd?: number;
  teamDailyLimitUsd?: number;
  requestsPerMinute?: number;
}): { token: string; record: V6ApiKeyRecord } {
  const token = `v6_${crypto.randomBytes(24).toString("hex")}`;
  const record: StoredKeyRecord = {
    id: crypto.randomUUID(),
    userId: params.userId,
    token,
    keyPreview: `${token.slice(0, 10)}...`,
    visibility: params.visibility ?? "public",
    isActive: true,
    dailySpendLimitUsd: params.dailySpendLimitUsd ?? 2,
    teamDailyLimitUsd: params.teamDailyLimitUsd ?? 10,
    requestsPerMinute: params.requestsPerMinute ?? 60
  };

  const keys = readKeys();
  keys.push(record);
  writeKeys(keys);

  const { token: _token, ...safe } = record;
  return { token, record: safe };
}

/**
 * Later, replace lookupV6ApiKey() with your real existing key store lookup.
 * Keep the returned shape the same so the rest of V6 does not change.
 */