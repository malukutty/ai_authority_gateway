import type { Commitment, Decision } from "./types.js";
export type AuditEvent = {
    ts: number;
    commitment: Commitment;
    decision: Decision;
};
export declare function writeAudit(evt: AuditEvent): void;
//# sourceMappingURL=audit.d.ts.map