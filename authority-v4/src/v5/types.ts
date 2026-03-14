import type { Commitment, Decision, Role, ActorLane } from "../core/types.js";

export type SourceSystem =
  | "zendesk"
  | "intercom"
  | "stripe"
  | "crm"
  | "billing_system"
  | "custom_application"
  | "other";

export interface ChatRequest {
  conversationId?: string;
  sourceSystem: SourceSystem;
  actorLane: ActorLane;
  role?: Role;
  env: Commitment["env"];
  customerMessage: string;
  policy: unknown;
}

export interface DetectedCommitment {
  detected: boolean;
  type: Commitment["type"];
  evidencePhrases: string[];
  amountCents?: number;
  currency?: string;
  confidence: number;
}

export interface V5ChatResponse {
  assistantDraft: string;
  detectedCommitment: DetectedCommitment;
  extractedCommitment: Commitment | null;
  decision: Decision | null;
  finalCustomerReply: string;
  auditId: string;
}

export interface BuildFinalReplyParams {
  customerMessage: string;
  assistantDraft: string;
  detectedCommitment: DetectedCommitment;
  decision: Decision | null;
}

export interface V5AuditEvent {
  ts: number;
  sourceSystem: SourceSystem;
  actorLane: ActorLane;
  role?: Role;
  env: Commitment["env"];
  customerMessage: string;
  assistantDraft: string;
  detectedCommitment: DetectedCommitment;
  extractedCommitment: Commitment | null;
  decision: Decision | null;
  finalCustomerReply: string;
}