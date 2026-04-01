import crypto from "node:crypto";
import {
  appendEvent,
} from "./store.js";
import type { UsageEvent } from "./types.js";

const AGENTS = [
  "agent_a91f",
  "agent_b73c",
  "agent_c204",
  "agent_d8aa",
  "agent_f13e",
  "agent_k72b",
  "agent_p44d",
  "agent_r91c",
];

const TASKS = [
  "task_debug_loop",
  "task_refactor_checkout",
  "task_write_tests",
  "task_fix_auth_bug",
  "task_codegen_cleanup",
  "task_schema_migration",
  "task_retry_patch",
  "task_ci_failure",
  "task_dependency_update",
  "task_eval_runner",
  "task_prod_hotfix",
  "task_docs_cleanup",
  "task_refactor_api",
  "task_migration_patch",
  "task_test_flake",
];

const USERS = ["user_4ac8", "user_82bf", "user_17de", "user_55a1"];
const TEAMS = ["team_eng", "team_platform", "team_ai", "team_ops"];
const MODELS = ["gpt-4o-mini", "gpt-4.1-mini"];

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randFloat(min: number, max: number): number {
  return Math.random() * (max - min) + min;
}

function weightedPickAgent(): string {
  const r = Math.random();
  if (r < 0.28) return "agent_a91f";
  if (r < 0.50) return "agent_b73c";
  if (r < 0.64) return "agent_c204";
  return pick(AGENTS);
}

function weightedPickTask(): string {
  const r = Math.random();
  if (r < 0.20) return "task_debug_loop";
  if (r < 0.35) return "task_refactor_checkout";
  if (r < 0.47) return "task_write_tests";
  if (r < 0.57) return "task_fix_auth_bug";
  return pick(TASKS);
}

function weightedStatus(): "allowed" | "alerted" | "blocked" {
  const r = Math.random();
  if (r < 0.84) return "allowed";
  if (r < 0.94) return "alerted";
  return "blocked";
}

function reasonForStatus(status: "allowed" | "alerted" | "blocked"): string | undefined {
  if (status === "blocked") {
    return pick([
      "Agent daily budget limit reached",
      "Team daily budget limit reached",
      "Per-key usage threshold exceeded",
    ]);
  }
  if (status === "alerted") {
    return pick([
      "Approaching agent daily budget limit",
      "Unusual retry pattern detected",
      "Team spend threshold warning",
    ]);
  }
  return undefined;
}

function computeCostUsd(inputTokens: number, outputTokens: number): number {
  const inputRate = 0.00000015;
  const outputRate = 0.0000006;
  return Number((inputTokens * inputRate + outputTokens * outputRate).toFixed(6));
}

function businessHourBiasTimestamp(daysBack = 30): string {
  const now = new Date();
  const past = new Date(now.getTime() - daysBack * 24 * 60 * 60 * 1000);

  const base = new Date(randInt(past.getTime(), now.getTime()));
  const hour = randInt(8, 18);
  const minute = randInt(0, 59);
  const second = randInt(0, 59);

  base.setUTCHours(hour, minute, second, 0);
  return base.toISOString();
}

function recentTimestamp(minutesBack = 20): string {
  const now = Date.now();
  const ts = now - randInt(0, minutesBack * 60 * 1000);
  return new Date(ts).toISOString();
}

function buildEvent(timestamp: string): UsageEvent {
  const status = weightedStatus();
  const agentId = weightedPickAgent();
  const taskId = weightedPickTask();
  const userId = pick(USERS);
  const teamId =
    agentId === "agent_a91f" || agentId === "agent_b73c"
      ? pick(["team_eng", "team_platform"])
      : pick(TEAMS);

  const model =
    agentId === "agent_a91f" || taskId === "task_debug_loop"
      ? pick(["gpt-4o-mini", "gpt-4.1-mini"])
      : pick(MODELS);

  let inputTokens = 0;
  let outputTokens = 0;
  let costUsd = 0;

  if (status !== "blocked") {
    const highCostAgent = agentId === "agent_a91f" || agentId === "agent_b73c";
    inputTokens = highCostAgent ? randInt(1200, 9000) : randInt(250, 4000);
    outputTokens = highCostAgent ? randInt(500, 3500) : randInt(100, 1800);

    if (status === "alerted") {
      inputTokens = Math.floor(inputTokens * randFloat(1.1, 1.6));
      outputTokens = Math.floor(outputTokens * randFloat(1.05, 1.4));
    }

    costUsd = computeCostUsd(inputTokens, outputTokens);
  }

  return {
    id: crypto.randomUUID(),
    timestamp,
    provider: "openai",
    model,
    agentId,
    taskId,
    userId,
    teamId,
    inputTokens,
    outputTokens,
    costUsd,
    status,
    reason: reasonForStatus(status),
    apiKeyId: "demo_public_key",
    ownerUserId: "demo-public",
    visibility: "public",
  };
}

export function seedPublicBackfill(count = 180): number {
  const events: UsageEvent[] = [];

  for (let i = 0; i < count; i++) {
    events.push(buildEvent(businessHourBiasTimestamp(30)));
  }

  events.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  for (const event of events) {
    appendEvent(event);
  }

  return events.length;
}

export function seedPublicTick(minEvents = 1, maxEvents = 3): number {
  const count = randInt(minEvents, maxEvents);

  const events: UsageEvent[] = [];
  for (let i = 0; i < count; i++) {
    events.push(buildEvent(recentTimestamp(20)));
  }

  events.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  for (const event of events) {
    appendEvent(event);
  }

  return events.length;
}
