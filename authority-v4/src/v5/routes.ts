import fs from "node:fs";
import path from "node:path";
import type { Express, Request, Response } from "express";
import { z } from "zod";
import { buildAssistantDraft } from "./chat.js";
import { detectCommitment } from "./detect.js";
import { extractStructuredCommitment } from "./extract.js";
import { buildFinalCustomerReply } from "./respond.js";
import { writeV5Audit } from "./audit.js";
import { DEMO_SCENARIOS } from "./scenarios.js";
import { evaluate } from "../core/evaluate.js";
import type { Commitment, Decision, Role } from "../core/types.js";
import type { PolicyConfig } from "../core/policy.js";
import crypto from "node:crypto";

const V5_AUDIT_PATH = process.env.AUTHORITY_V5_AUDIT_PATH || "./authority-v5.audit.jsonl";

const ActorLaneZ = z.enum(["ai_agent", "human_agent", "human_manager"]);
const RoleZ = z.enum(["agent", "team_lead", "manager", "finance_manager", "director"]);
const EnvZ = z.enum(["dev", "prod"]);
const SourceSystemZ = z.enum([
  "zendesk",
  "intercom",
  "stripe",
  "crm",
  "billing_system",
  "custom_application",
  "other"
]);

const LaneThresholdZ = z.object({
  autoExecuteUpTo: z.number().int().min(0),
  requireManagerAbove: z.number().int().min(0),
  requireDirectorAbove: z.number().int().min(0)
});

const PolicyZ = z.object({
  killSwitch: z.boolean(),
  denyByDefault: z.boolean(),
  thresholds: z.object({
    ai_agent: LaneThresholdZ,
    human_agent: LaneThresholdZ,
    human_manager: LaneThresholdZ
  }),
  commitmentEnabled: z.record(z.boolean()).optional(),
  hardStopRules: z
    .object({
      customerFlagged: z.boolean().optional(),
      tooManyRefundsIn30Days: z.boolean().optional(),
      refundAbovePercentAnnualValue: z.boolean().optional()
    })
    .optional()
});

const ChatEvaluateRequestZ = z.object({
  conversationId: z.string().optional(),
  sourceSystem: SourceSystemZ,
  actorLane: ActorLaneZ,
  role: RoleZ.optional(),
  env: EnvZ,
  customerMessage: z.string().min(1).max(5000),
  policy: PolicyZ
});

type V5AuditRecord = {
  id: string;
  ts: number;
  sourceSystem?: string;
  actorLane?: "ai_agent" | "human_agent" | "human_manager";
  role?: string;
  env?: "dev" | "prod";
  customerMessage?: string;
  assistantDraft?: string;
  detectedCommitment?: {
    detected?: boolean;
    type?: "refund" | "credit" | "unknown";
    evidencePhrases?: string[];
    amountCents?: number;
    amountKnown?: boolean;
    currency?: string;
    confidence?: number;
  } | null;
  extractedCommitment?: {
    type?: "refund" | "credit" | "unknown";
    env?: "dev" | "prod";
    actorLane?: "ai_agent" | "human_agent" | "human_manager";
    role?: string;
    amountCents?: number;
    currency?: string;
  } | null;
  decision?: {
    decisionId?: string;
    status?: "allow" | "deny" | "escalate";
    riskScore?: number;
    decisionExplainer?: string;
    policyPath?: string[];
    requiredApprovalChain?: string[];
  } | null;
  finalCustomerReply?: string;
};

function roleForUnknownDetectedType(role?: Role): Role | undefined {
  return role;
}

function readAllV5Audit(): V5AuditRecord[] {
  const filePath = path.resolve(V5_AUDIT_PATH);

  if (!fs.existsSync(filePath)) {
    return [];
  }

  const lines = fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  return lines
    .map((line) => {
      try {
        return JSON.parse(line) as V5AuditRecord;
      } catch {
        return null;
      }
    })
    .filter(Boolean) as V5AuditRecord[];
}

function readRecentV5Audit(limit = 20) {
  return readAllV5Audit().slice(-limit).reverse();
}

function buildV5Summary(events: V5AuditRecord[]) {
  const totalMessages = events.length;
  const commitmentsDetected = events.filter((e) => e.detectedCommitment?.detected).length;
  const allowed = events.filter((e) => e.decision?.status === "allow").length;
  const escalated = events.filter((e) => e.decision?.status === "escalate").length;
  const denied = events.filter((e) => e.decision?.status === "deny").length;

  const totalRiskScore = events.reduce((sum, e) => sum + (e.decision?.riskScore ?? 0), 0);
  const averageRiskScore = totalMessages > 0 ? Math.round(totalRiskScore / totalMessages) : 0;

  const totalExposureCents = events.reduce(
    (sum, e) => sum + (e.extractedCommitment?.amountCents ?? 0),
    0
  );
  const exposureAllowedCents = events
    .filter((e) => e.decision?.status === "allow")
    .reduce((sum, e) => sum + (e.extractedCommitment?.amountCents ?? 0), 0);
  const exposureRequiringApprovalCents = events
    .filter((e) => e.decision?.status === "escalate")
    .reduce((sum, e) => sum + (e.extractedCommitment?.amountCents ?? 0), 0);
  const exposurePreventedCents = events
    .filter((e) => e.decision?.status === "deny")
    .reduce((sum, e) => sum + (e.extractedCommitment?.amountCents ?? 0), 0);

  const byCommitmentType = ["refund", "credit", "unknown"].map((type) => {
    const scoped = events.filter((e) => (e.detectedCommitment?.type ?? "unknown") === type);
    return {
      type,
      count: scoped.length,
      allowed: scoped.filter((e) => e.decision?.status === "allow").length,
      escalated: scoped.filter((e) => e.decision?.status === "escalate").length,
      denied: scoped.filter((e) => e.decision?.status === "deny").length
    };
  });

  const byLane = ["ai_agent", "human_agent", "human_manager"].map((lane) => {
    const scoped = events.filter((e) => e.actorLane === lane);
    const laneRisk = scoped.reduce((sum, e) => sum + (e.decision?.riskScore ?? 0), 0);
    return {
      lane,
      count: scoped.length,
      allowed: scoped.filter((e) => e.decision?.status === "allow").length,
      escalated: scoped.filter((e) => e.decision?.status === "escalate").length,
      denied: scoped.filter((e) => e.decision?.status === "deny").length,
      avgRisk: scoped.length > 0 ? Math.round(laneRisk / scoped.length) : 0
    };
  });

  const policyPatternCounts = new Map<string, number>();
  for (const event of events) {
    const pattern =
      event.decision?.policyPath && event.decision.policyPath.length > 0
        ? event.decision.policyPath.join(" → ")
        : "no_policy_path";
    policyPatternCounts.set(pattern, (policyPatternCounts.get(pattern) ?? 0) + 1);
  }

  const policyPatterns = Array.from(policyPatternCounts.entries())
    .map(([pattern, count]) => ({
      pattern,
      count,
      pct: totalMessages > 0 ? Math.round((count / totalMessages) * 100) : 0
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const topHighRiskEvents = [...events]
    .sort((a, b) => (b.decision?.riskScore ?? 0) - (a.decision?.riskScore ?? 0))
    .slice(0, 10)
    .map((e) => ({
      id: e.id,
      timestamp: new Date(e.ts).toISOString(),
      customerMessage: e.customerMessage ?? "",
      commitmentType: e.detectedCommitment?.type ?? "unknown",
      lane: e.actorLane ?? "unknown",
      role: e.role ?? "unknown",
      amountCents: e.extractedCommitment?.amountCents ?? 0,
      status: e.decision?.status ?? "none",
      riskScore: e.decision?.riskScore ?? 0,
      decisionExplainer: e.decision?.decisionExplainer ?? "",
      policyPath: e.decision?.policyPath ?? [],
      finalCustomerReply: e.finalCustomerReply ?? ""
    }));

  return {
    generatedAt: new Date().toISOString(),
    source: "v5_audit",
    eventCount: totalMessages,
    totals: {
      totalMessages,
      commitmentsDetected,
      allowed,
      escalated,
      denied,
      averageRiskScore
    },
    financials: {
      totalExposureCents,
      exposureAllowedCents,
      exposureRequiringApprovalCents,
      exposurePreventedCents
    },
    byCommitmentType,
    byLane,
    policyPatterns,
    topHighRiskEvents
  };
}

function buildEscalateDecision(
  reason: string,
  policyPath: string[],
  requiredApprovalChain: Role[] = ["team_lead", "manager"]
): Decision {
  return {
    decisionId: crypto.randomUUID(),
    status: "escalate",
    riskScore: 75,
    decisionExplainer: reason,
    policyPath,
    requiredApprovalChain
  };
}

function shouldEscalateUnknownFinancialAmount(
  detectedCommitment: { detected: boolean; type: "refund" | "credit" | "unknown"; amountKnown: boolean }
): boolean {
  if (!detectedCommitment.detected) return false;
  if (detectedCommitment.type !== "refund" && detectedCommitment.type !== "credit") return false;
  return !detectedCommitment.amountKnown;
}

function shouldEscalateUnknownCommitmentType(
  detectedCommitment: { detected: boolean; type: "refund" | "credit" | "unknown" }
): boolean {
  if (!detectedCommitment.detected) return false;
  return detectedCommitment.type === "unknown";
}

export function mountV5Routes(app: Express) {
  app.get("/v5/health", (_req: Request, res: Response) => {
    return res.json({ status: "ok", version: "v5" });
  });

  app.get("/v5/scenarios", (_req: Request, res: Response) => {
    return res.json({ scenarios: DEMO_SCENARIOS });
  });

  app.get("/v5/audit/recent", (req: Request, res: Response) => {
    const rawLimit = Number(req.query.limit ?? 20);
    const limit = Number.isFinite(rawLimit)
      ? Math.max(1, Math.min(100, Math.floor(rawLimit)))
      : 20;

    return res.json({ events: readRecentV5Audit(limit) });
  });

  app.get("/v5/report/summary", (_req: Request, res: Response) => {
    const events = readAllV5Audit();
    return res.json(buildV5Summary(events));
  });

  app.post("/v5/chat/evaluate", (req: Request, res: Response) => {
    const parsed = ChatEvaluateRequestZ.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
    }

    const { sourceSystem, actorLane, role, env, customerMessage, policy } = parsed.data;

    const assistantDraft = buildAssistantDraft(customerMessage);
    const detectedCommitment = detectCommitment(assistantDraft, customerMessage);

    const extractedCommitment = extractStructuredCommitment({
      actorLane,
      role: roleForUnknownDetectedType(role),
      env,
      detected: detectedCommitment
    });

    let decision: Decision | null = null;

    if (shouldEscalateUnknownFinancialAmount(detectedCommitment)) {
      decision = buildEscalateDecision(
        "Requires approval: financial commitment detected but amount is unspecified.",
        ["commitment_detected", "unknown_amount", "require_approval"]
      );
    } else if (shouldEscalateUnknownCommitmentType(detectedCommitment)) {
      decision = buildEscalateDecision(
        "Requires approval: commitment detected but type requires human review.",
        ["commitment_detected", "unknown_type", "require_approval"]
      );
    } else if (detectedCommitment.detected && extractedCommitment) {
      decision = evaluate(extractedCommitment as Commitment, policy as PolicyConfig);
    }

    const finalCustomerReply = buildFinalCustomerReply({
      customerMessage,
      assistantDraft,
      detectedCommitment,
      decision
    });

    const auditId = writeV5Audit({
      ts: Date.now(),
      sourceSystem,
      actorLane,
      role,
      env,
      customerMessage,
      assistantDraft,
      detectedCommitment,
      extractedCommitment,
      decision,
      finalCustomerReply
    });

    return res.json({
      assistantDraft,
      detectedCommitment,
      extractedCommitment,
      decision,
      finalCustomerReply,
      auditId
    });
  });
} 