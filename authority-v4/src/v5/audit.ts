import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";
import type { V5AuditEvent } from "./types.js";

const DEFAULT_PATH = process.env.AUTHORITY_V5_AUDIT_PATH || "./authority-v5.audit.jsonl";

export function writeV5Audit(evt: V5AuditEvent): string {
  const id = randomUUID();
  const filePath = path.resolve(DEFAULT_PATH);
  fs.appendFileSync(filePath, JSON.stringify({ id, ...evt }) + "\n", "utf8");
  return id;
}