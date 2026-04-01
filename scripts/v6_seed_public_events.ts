import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

type EventStatus = "allowed" | "alerted" | "blocked";
type Visibility = "public" | "private";
type Provider = "openai" | "anthropic";

type UsageEvent = {
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
  apiKeyId?: string;
  ownerUserId?: string;
  visibility: Visibility;
};

const EVENTS_PATH =
  process.env.AUTHORITY_V6_EVENTS_PATH || "./authority-v6.events.jsonl";

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

function resolvePath(): string {
  return path.resolve(EVENTS_PATH);
}

function ensureDir(filePath: string) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function appendEvents(events: UsageEvent[]) {
  const filePath = resolvePath();
  ensureDir(filePath);
  const payload = events.map((e) => JSON.stringify(e)).join("\n") + "\n";
  fs.appendFileSync(filePath, payload, "utf8");
}

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

function weightedStatus(): EventStatus {
  const r = Math.random();
  if (r < 0.84) return "allowed";
  if (r < 0.94) return "alerted";
  return "blocked";
}

function reasonForStatus(status: EventStatus): string | undefined {
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
  // Believable, not exact billing. Enough for dashboard realism.
  const inputRate = 0.00000015;
  const outputRate = 0.0000006;
  return Number((inputTokens * inputRate + outputTokens * outputRate).toFixed(6));
}

function businessHourBiasTimestamp(daysBack = 30): string {
  const now = new Date();
  const past = new Date(now.getTime() - daysBack * 24 * 60 * 60 * 1000);

  const base = new Date(randInt(past.getTime(), now.getTime()));

  // Bias toward weekday work hours
  const weekday = randInt(1, 5); // Mon-Fri-ish
  const hour = randInt(8, 18);
  const minute = randInt(0, 59);
  const second = randInt(0, 59);

  // Snap toward a recent realistic working timestamp sometimes
  if (Math.random() < 0.65) {
    const dayOffset = randInt(0, daysBack);
    const d = new Date(now.getTime() - dayOffset * 24 * 60 * 60 * 1000);
    const currentDow = d.getUTCDay();
    const shift = ((weekday - currentDow + 7) % 7);
    d.setUTCDate(d.getUTCDate() + shift);
    d.setUTCHours(hour, minute, second, 0);
    return d.toISOString();
  }

  base.setUTCHours(hour, minute, second, 0);
  return base.toISOString();
}

function recentTimestamp(minutesBack = 30): string {
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

function backfill(count = 180) {
  const events: UsageEvent[] = [];
  for (let i = 0; i < count; i++) {
    events.push(buildEvent(businessHourBiasTimestamp(30)));
  }
  // sort oldest to newest so file has sane chronological order
  events.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  appendEvents(events);
  console.log(`Backfilled ${events.length} public demo events into ${resolvePath()}`);
}

function tick(minEvents = 1, maxEvents = 3) {
  const count = randInt(minEvents, maxEvents);
  const events: UsageEvent[] = [];
  for (let i = 0; i < count; i++) {
    events.push(buildEvent(recentTimestamp(20)));
  }
  events.sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  appendEvents(events);
  console.log(`Appended ${events.length} recent public demo events into ${resolvePath()}`);
}

function usage() {
  console.log(`
Usage:
  npx tsx scripts/v6_seed_public_events.ts backfill
  npx tsx scripts/v6_seed_public_events.ts tick

Optional env:
  AUTHORITY_V6_EVENTS_PATH=/path/to/authority-v6.events.jsonl
`);
}

const mode = process.argv[2];

if (!mode) {
  usage();
  process.exit(1);
}

if (mode === "backfill") {
  backfill();
  process.exit(0);
}

if (mode === "tick") {
  tick();
  process.exit(0);
}

usage();
process.exit(1); 