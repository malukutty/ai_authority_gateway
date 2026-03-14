import type { Commitment } from "../core/types.js";
import type { DetectedCommitment } from "./types.js";

export function extractStructuredCommitment(params: {
  actorLane: Commitment["actorLane"];
  role?: Commitment["role"];
  env: Commitment["env"];
  detected: DetectedCommitment;
}): Commitment | null {
  if (!params.detected.detected) return null;

  return {
    type: params.detected.type,
    env: params.env,
    actorLane: params.actorLane,
    role: params.role,
    amountCents: params.detected.amountCents ?? 0,
    currency: params.detected.currency ?? "usd"
  };
}