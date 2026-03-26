import type { BudgetPolicy, UsageEvent } from "./types.js";

export const DEFAULT_POLICY: BudgetPolicy = {
  agentDailyLimitUsd: 100,
  teamDailyLimitUsd: 500,
  alertThresholdPct: 80,
  blockThresholdPct: 100
};

export function evaluateBudgetPolicy(params: {
  policy: BudgetPolicy;
  projectedAgentSpendUsd: number;
  projectedTeamSpendUsd: number;
}): {
  shouldBlock: boolean;
  shouldAlert: boolean;
  reason?: string;
} {
  const { policy, projectedAgentSpendUsd, projectedTeamSpendUsd } = params;

  const agentBlockThreshold = policy.agentDailyLimitUsd * (policy.blockThresholdPct / 100);
  const teamBlockThreshold = policy.teamDailyLimitUsd * (policy.blockThresholdPct / 100);
  const agentAlertThreshold = policy.agentDailyLimitUsd * (policy.alertThresholdPct / 100);
  const teamAlertThreshold = policy.teamDailyLimitUsd * (policy.alertThresholdPct / 100);

  if (projectedAgentSpendUsd >= agentBlockThreshold) {
    return {
      shouldBlock: true,
      shouldAlert: true,
      reason: "Agent daily budget limit reached"
    };
  }

  if (projectedTeamSpendUsd >= teamBlockThreshold) {
    return {
      shouldBlock: true,
      shouldAlert: true,
      reason: "Team daily budget limit reached"
    };
  }

  if (projectedAgentSpendUsd >= agentAlertThreshold) {
    return {
      shouldBlock: false,
      shouldAlert: true,
      reason: "Agent approaching daily budget limit"
    };
  }

  if (projectedTeamSpendUsd >= teamAlertThreshold) {
    return {
      shouldBlock: false,
      shouldAlert: true,
      reason: "Team approaching daily budget limit"
    };
  }

  return {
    shouldBlock: false,
    shouldAlert: false
  };
}

export function getEventStatus(params: {
  blocked: boolean;
  alerted: boolean;
}): UsageEvent["status"] {
  if (params.blocked) return "blocked";
  if (params.alerted) return "alerted";
  return "allowed";
}