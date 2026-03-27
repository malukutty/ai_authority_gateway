import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { AgentSummary, BudgetPolicy, SpendSummary, UsageEvent, Visibility } from "./types.js";
import { DEFAULT_POLICY } from "./policy.js";

const V6_EVENTS_PATH = process.env.AUTHORITY_V6_EVENTS_PATH || "./authority-v6.events.jsonl";

let currentPolicy: BudgetPolicy = { ...DEFAULT_POLICY };

function resolvePath() {
  return path.resolve(V6_EVENTS_PATH);
}

export function createEventId(): string {
  return crypto.randomUUID();
}

export function getPolicy(): BudgetPolicy {
  return currentPolicy;
}

export function setPolicy(next: Partial<BudgetPolicy>): BudgetPolicy {
  currentPolicy = {
    ...currentPolicy,
    ...next
  };
  return currentPolicy;
}

export function appendEvent(event: UsageEvent): void {
  const filePath = resolvePath();
  fs.appendFileSync(filePath, `${JSON.stringify(event)}\n`, "utf8");
}

export function readAllEvents(): UsageEvent[] {
  const filePath = resolvePath();
  if (!fs.existsSync(filePath)) return [];

  return fs
    .readFileSync(filePath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line) as UsageEvent;
      } catch {
        return null;
      }
    })
    .filter(Boolean) as UsageEvent[];
}

function isSameUtcDay(aIso: string, b: Date): boolean {
  const a = new Date(aIso);
  return (
    a.getUTCFullYear() === b.getUTCFullYear() &&
    a.getUTCMonth() === b.getUTCMonth() &&
    a.getUTCDate() === b.getUTCDate()
  );
}

export function readTodayEvents(now = new Date()): UsageEvent[] {
  return readAllEvents().filter((e) => isSameUtcDay(e.timestamp, now));
}

export function getAgentSpendToday(agentId: string, apiKeyId?: string): number {
  return readTodayEvents()
    .filter((e) => e.agentId === agentId && (!apiKeyId || e.apiKeyId === apiKeyId))
    .reduce((sum, e) => sum + e.costUsd, 0);
}

export function getTeamSpendToday(teamId: string, apiKeyId?: string): number {
  return readTodayEvents()
    .filter((e) => e.teamId === teamId && (!apiKeyId || e.apiKeyId === apiKeyId))
    .reduce((sum, e) => sum + e.costUsd, 0);
}

function filterEventsForVisibility(params: {
  visibility?: Visibility;
  ownerUserId?: string;
}): UsageEvent[] {
  const { visibility, ownerUserId } = params;
  const events = readTodayEvents();

  if (visibility === "public") {
    return events.filter((e) => e.visibility === "public");
  }

  if (visibility === "private" && ownerUserId) {
    return events.filter((e) => e.ownerUserId === ownerUserId);
  }

  return events;
}

export function getSummary(params?: {
  visibility?: Visibility;
  ownerUserId?: string;
}): SpendSummary {
  const events = filterEventsForVisibility({
    visibility: params?.visibility,
    ownerUserId: params?.ownerUserId
  });

  const activeAgents = new Set(events.map((e) => e.agentId)).size;
  const teamsTracked = new Set(events.map((e) => e.teamId)).size;

  return {
    spendToday: Number(events.reduce((sum, e) => sum + e.costUsd, 0).toFixed(6)),
    activeAgents,
    blockedRequests: events.filter((e) => e.status === "blocked").length,
    alertsTriggered: events.filter((e) => e.status === "alerted").length,
    teamsTracked
  };
}

export function getAgentSummaries(params?: {
  visibility?: Visibility;
  ownerUserId?: string;
}): AgentSummary[] {
  let events = readAllEvents();

  if (params?.visibility === "public") {
    events = events.filter((e) => e.visibility === "public");
  } else if (params?.visibility === "private" && params.ownerUserId) {
    events = events.filter((e) => e.ownerUserId === params.ownerUserId);
  }

  const grouped = new Map<string, UsageEvent[]>();

  for (const event of events) {
    const key = `${event.agentId}::${event.teamId}::${event.userId}`;
    const bucket = grouped.get(key) ?? [];
    bucket.push(event);
    grouped.set(key, bucket);
  }

  return Array.from(grouped.values())
    .map((rows): AgentSummary => {
      const sortedRows = [...rows].sort(
        (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      const first = sortedRows[0];
      const latest = sortedRows[sortedRows.length - 1];
      const spendTotal = sortedRows.reduce((sum, e) => sum + e.costUsd, 0);

      let status: AgentSummary["status"];
      if (latest.status === "blocked") {
        status = "blocked";
      } else if (latest.status === "alerted") {
        status = "limited";
      } else {
        status = "active";
      }

      return {
        agentId: first.agentId,
        teamId: first.teamId,
        userId: first.userId,
        requestCount: sortedRows.length,
        spendToday: Number(spendTotal.toFixed(6)),
        avgCostPerRequest: Number((spendTotal / sortedRows.length).toFixed(6)),
        lastSeen: latest.timestamp,
        status
      };
    })
    .sort((a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime());
}

export function getRecentEvents(limit = 50, params?: {
  visibility?: Visibility;
  ownerUserId?: string;
}): UsageEvent[] {
  let events = readAllEvents();

  if (params?.visibility === "public") {
    events = events.filter((e) => e.visibility === "public");
  } else if (params?.visibility === "private" && params.ownerUserId) {
    events = events.filter((e) => e.ownerUserId === params.ownerUserId);
  }

  return events.slice(-limit).reverse();
} 