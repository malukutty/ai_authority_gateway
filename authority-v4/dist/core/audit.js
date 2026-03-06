import fs from "node:fs";
import path from "node:path";
const DEFAULT_PATH = process.env.AUTHORITY_AUDIT_PATH || "./authority-v4.audit.jsonl";
export function writeAudit(evt) {
    const filePath = path.resolve(DEFAULT_PATH);
    fs.appendFileSync(filePath, JSON.stringify(evt) + "\n", "utf8");
}
//# sourceMappingURL=audit.js.map