export type CommitmentType = "refund" | "credit" | "unknown";

export type ActorLane = "ai_agent" | "human_agent" | "human_manager";

export type Role = "agent" | "team_lead" | "manager" | "finance_manager" | "director";

export interface Commitment {
  type: CommitmentType;
  env: "dev" | "prod";

  actorLane: ActorLane;
  role?: Role;

  amountCents: number;
  currency: string;

  orderId?: string;
  customerId?: string;
}

export interface Decision {
  decisionId?: string;
  status: "allow" | "deny" | "escalate";
  riskScore: number;
  decisionExplainer: string;
  policyPath: string[];
  requiredApprovalChain: Role[];
}