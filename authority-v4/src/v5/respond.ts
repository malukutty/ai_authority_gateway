import type { BuildFinalReplyParams } from "./types.js";

export function buildFinalCustomerReply(params: BuildFinalReplyParams): string {
  const { detectedCommitment, decision, assistantDraft } = params;

  if (!detectedCommitment.detected) {
    return assistantDraft;
  }

  if (!decision) {
    return "I’m reviewing this request and will follow up shortly.";
  }

  if (decision.status === "allow") {
    return assistantDraft;
  }

  if (decision.status === "escalate") {
    return "I’ve flagged this for review and our team will follow up shortly.";
  }

  return "I’m not able to confirm that yet. I’ve sent this for further review.";
}