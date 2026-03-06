import fs from "node:fs";
import path from "node:path";
import type { Commitment, Decision } from "./types.js";

export type AuditEvent = {
  ts: number;
  commitment: Commitment;
  decision: Decision;
};

const DEFAULT_PATH = process.env.AUTHORITY_AUDIT_PATH || "./authority-v4.audit.jsonl";

export function writeAudit(evt: AuditEvent) {
  const filePath = path.resolve(DEFAULT_PATH);
  fs.appendFileSync(filePath, JSON.stringify(evt) + "\n", "utf8");
}