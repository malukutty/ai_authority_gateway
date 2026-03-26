export type Provider = "openai" | "anthropic";
export type EventStatus = "allowed" | "alerted" | "blocked";

export interface AttributionHeaders {
  agentId: string;
  taskId: string;
  userId: string;
  teamId: string;
}

export interface UsageEvent {
  id: string;
  timestamp: string;
  provider: Provider;
  model: string;
  agentId: string;
  taskId: string;
  userId: string;
  teamId: string;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
  status: EventStatus;
  reason?: string;
}

export interface BudgetPolicy {
  agentDailyLimitUsd: number;
  teamDailyLimitUsd: number;
  alertThresholdPct: number;
  blockThresholdPct: number;
}

export interface SpendSummary {
  spendToday: number;
  activeAgents: number;
  blockedRequests: number;
  alertsTriggered: number;
  teamsTracked: number;
}

export interface AgentSummary {
  agentId: string;
  teamId: string;
  userId: string;
  requestCount: number;
  spendToday: number;
  avgCostPerRequest: number;
  lastSeen: string;
  status: "active" | "limited" | "blocked";
}