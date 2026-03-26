import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import type { AgentSummary, BudgetPolicy, SpendSummary, UsageEvent } from "./types.js";
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

export function getAgentSpendToday(agentId: string): number {
  return readTodayEvents()
    .filter((e) => e.agentId === agentId)
    .reduce((sum, e) => sum + e.costUsd, 0);
}

export function getTeamSpendToday(teamId: string): number {
  return readTodayEvents()
    .filter((e) => e.teamId === teamId)
    .reduce((sum, e) => sum + e.costUsd, 0);
}

export function getSummary(): SpendSummary {
  const events = readTodayEvents();
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

export function getAgentSummaries(): AgentSummary[] {
  const events = readTodayEvents();
  const grouped = new Map<string, UsageEvent[]>();

  for (const event of events) {
    const key = `${event.agentId}::${event.teamId}::${event.userId}`;
    const bucket = grouped.get(key) ?? [];
    bucket.push(event);
    grouped.set(key, bucket);
  }

  return Array.from(grouped.values()).map((rows) => {
    const first = rows[0];
    const spendToday = rows.reduce((sum, e) => sum + e.costUsd, 0);
    const blocked = rows.some((e) => e.status === "blocked");
    const alerted = rows.some((e) => e.status === "alerted");
    return {
      agentId: first.agentId,
      teamId: first.teamId,
      userId: first.userId,
      requestCount: rows.length,
      spendToday: Number(spendToday.toFixed(6)),
      avgCostPerRequest: Number((spendToday / rows.length).toFixed(6)),
      lastSeen: rows[rows.length - 1]?.timestamp ?? first.timestamp,
      status: blocked ? "blocked" : alerted ? "limited" : "active"
    };
  });
}

export function getRecentEvents(limit = 50): UsageEvent[] {
  return readAllEvents().slice(-limit).reverse();
}