import * as Sentry from "@sentry/node";
import { randomUUID } from "node:crypto";
import type { Commitment, Decision, ActorLane, Role } from "./types.js";
import type { PolicyConfig } from "./policy.js";

function clampInt(n: number, min: number, max: number) {
  const x = Math.floor(Number.isFinite(n) ? n : 0);
  return Math.max(min, Math.min(max, x));
}

function roleRank(role: Role): number {
  switch (role) {
    case "director":
      return 4;
    case "finance_manager":
      return 3;
    case "manager":
      return 2;
    case "team_lead":
      return 1;
    default:
      return 0;
  }
}

function requiredRoleForAmount(
  lane: ActorLane,
  amountCents: number,
  policy: PolicyConfig
): Role | null {
  const t = policy.thresholds[lane];
  if (!t) return policy.denyByDefault ? "team_lead" : null;

  if (amountCents <= t.autoExecuteUpTo) return null;
  if (amountCents > t.requireDirectorAbove) return "director";
  if (amountCents > t.requireManagerAbove) return "manager";

  return "team_lead";
}

export function evaluate(commitment: Commitment, policy: PolicyConfig): Decision {
  const decisionId = randomUUID();
  const amountCents = clampInt(commitment.amountCents ?? 0, 0, 50_000_000);

  if (policy.killSwitch) {
    return {
      decisionId,
      status: "deny",
      riskScore: 100,
      decisionExplainer: "Blocked: kill switch is enabled.",
      policyPath: ["kill_switch"],
      requiredApprovalChain: ["team_lead"],
    };
  }

  if (policy.commitmentEnabled && policy.commitmentEnabled[commitment.type] === false) {
    return {
      decisionId,
      status: "deny",
      riskScore: 90,
      decisionExplainer: `Blocked: commitment type '${commitment.type}' is disabled by policy.`,
      policyPath: ["commitment_type_disabled"],
      requiredApprovalChain: ["team_lead"],
    };
  }

  if (policy.hardStopRules?.customerFlagged) {
    return {
      decisionId,
      status: "escalate",
      riskScore: 95,
      decisionExplainer: "Escalated: customer is flagged. Requires review.",
      policyPath: ["hard_stop", "customer_flagged"],
      requiredApprovalChain: ["finance_manager"],
    };
  }

  const lane = commitment.actorLane;
  const actorRole = commitment.role ?? "agent";
  const required = requiredRoleForAmount(lane, amountCents, policy);

  if (!required) {
    return {
      decisionId,
      status: "allow",
      riskScore: 20,
      decisionExplainer: "Allowed: within auto-execute threshold.",
      policyPath: ["threshold_check", "allow"],
      requiredApprovalChain: [],
    };
  }

  if (roleRank(actorRole) >= roleRank(required)) {
    return {
      decisionId,
      status: "allow",
      riskScore: 25,
      decisionExplainer: `Allowed: actor role '${actorRole}' satisfies required role '${required}'.`,
      policyPath: ["threshold_check", "role_satisfies", "allow"],
      requiredApprovalChain: [],
    };
  }

  const chain: Role[] =
    required === "director"
      ? ["team_lead", "manager", "director"]
      : required === "manager"
        ? ["team_lead", "manager"]
        : ["team_lead"];

  return {
    decisionId,
    status: "escalate",
    riskScore: 75,
    decisionExplainer: `Requires approval: amount exceeds lane threshold. Required role: ${required}.`,
    policyPath: ["threshold_check", "require_approval"],
    requiredApprovalChain: chain,
  };
}