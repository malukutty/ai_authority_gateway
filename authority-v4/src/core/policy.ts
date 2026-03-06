import type { ActorLane, CommitmentType } from "./types.js";

export interface LaneThreshold {
  autoExecuteUpTo: number;      // cents
  requireManagerAbove: number;  // cents
  requireDirectorAbove: number; // cents
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