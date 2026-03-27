import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { V6ApiKeyRecord, Visibility } from "./types.js";

const V6_KEYS_PATH = process.env.AUTHORITY_V6_KEYS_PATH || "./authority-v6.keys.json";

type StoredKeyRecord = V6ApiKeyRecord & {
  token: string;
};

const SEEDED_KEYS: StoredKeyRecord[] = [
  {
    id: "seed-public-key",
    userId: "public-user",
    token: "v6_test_public_key_123",
    keyPreview: "v6_test_pu...",
    visibility: "public",
    isActive: true,
    dailySpendLimitUsd: 1,
    teamDailyLimitUsd: 2,
    requestsPerMinute: 60
  }
];

function resolvePath() {
  return path.resolve(V6_KEYS_PATH);
}

function dedupeKeys(keys: StoredKeyRecord[]): StoredKeyRecord[] {
  const byToken = new Map<string, StoredKeyRecord>();
  for (const key of keys) {
    byToken.set(key.token, key);
  }
  return Array.from(byToken.values());
}

function readKeys(): StoredKeyRecord[] {
  const filePath = resolvePath();

  let fileKeys: StoredKeyRecord[] = [];

  if (fs.existsSync(filePath)) {
    try {
      fileKeys = JSON.parse(fs.readFileSync(filePath, "utf8")) as StoredKeyRecord[];
    } catch {
      fileKeys = [];
    }
  }

  return dedupeKeys([...SEEDED_KEYS, ...fileKeys]);
}

function writeKeys(keys: StoredKeyRecord[]) {
  const filePath = resolvePath();
  fs.writeFileSync(filePath, JSON.stringify(dedupeKeys(keys), null, 2), "utf8");
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

export function listV6ApiKeys(): V6ApiKeyRecord[] {
  return readKeys().map(({ token: _token, ...safe }) => safe);
}

export function deactivateV6ApiKey(rawToken: string): boolean {
  const keys = readKeys();
  const index = keys.findIndex((k) => k.token === rawToken);
  if (index === -1) return false;

  keys[index] = {
    ...keys[index],
    isActive: false
  };

  writeKeys(keys);
  return true;
}