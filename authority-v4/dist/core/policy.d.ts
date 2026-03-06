import type { ActorLane, CommitmentType } from "./types.js";
export interface LaneThreshold {
    autoExecuteUpTo: number;
    requireManagerAbove: number;
    requireDirectorAbove: number;
}
export interface HardStopRules {
    customerFlagged?: boolean;
    tooManyRefundsIn30Days?: boolean;
    refundAbovePercentAnnualValue?: boolean;
}
export interface PolicyConfig {
    killSwitch: boolean;
    denyByDefault: boolean;
    thresholds: Record<ActorLane, LaneThreshold>;
    commitmentEnabled?: Partial<Record<CommitmentType, boolean>>;
    hardStopRules?: HardStopRules;
}
//# sourceMappingURL=policy.d.ts.map