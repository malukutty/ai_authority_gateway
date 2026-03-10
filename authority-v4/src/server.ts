require("../instrument");

import * as Sentry from "@sentry/node";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import cors from "cors";
import { z } from "zod";
import { evaluate } from "./core/evaluate.js";
import type { Commitment } from "./core/types.js";
import type { PolicyConfig } from "./core/policy.js";
import { writeAudit } from "./core/audit.js";

const app = express();

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://authority.bhaviavelayudhan.com",
];

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json({ limit: "256kb" }));

const ActorLaneZ = z.enum(["ai_agent", "human_agent", "human_manager"]);
const RoleZ = z.enum(["agent", "team_lead", "manager", "finance_manager", "director"]);
const EnvZ = z.enum(["dev", "prod"]);
const CommitmentTypeZ = z.enum(["refund", "credit", "unknown"]);

const LaneThresholdZ = z.object({
  autoExecuteUpTo: z.number().int().min(0),
  requireManagerAbove: z.number().int().min(0),
  requireDirectorAbove: z.number().int().min(0),
});

const PolicyZ = z.object({
  killSwitch: z.boolean(),
  denyByDefault: z.boolean(),
  thresholds: z.object({
    ai_agent: LaneThresholdZ,
    human_agent: LaneThresholdZ,
    human_manager: LaneThresholdZ,
  }),
  commitmentEnabled: z.record(z.boolean()).optional(),
  hardStopRules: z
    .object({
      customerFlagged: z.boolean().optional(),
      tooManyRefundsIn30Days: z.boolean().optional(),
      refundAbovePercentAnnualValue: z.boolean().optional(),
    })
    .optional(),
});

const EvaluateRequestZ = z.object({
  commitment: z.object({
    type: CommitmentTypeZ,
    env: EnvZ,
    actorLane: ActorLaneZ,
    role: RoleZ.optional(),
    amountCents: z.number().int().min(0).max(50_000_000),
    currency: z.string().min(1).max(8),
    orderId: z.string().optional(),
    customerId: z.string().optional(),
  }),
  policy: PolicyZ,
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/v4/audit/recent", (_req, res) => {
  try {
    const filePath = path.resolve(
      process.env.AUTHORITY_AUDIT_PATH || "./authority-v4.audit.jsonl"
    );

    if (!fs.existsSync(filePath)) {
      return res.json({ events: [] });
    }

    const raw = fs.readFileSync(filePath, "utf8").trim();
    if (!raw) {
      return res.json({ events: [] });
    }

    const events = raw
      .split("\n")
      .filter(Boolean)
      .slice(-50)
      .map((line) => JSON.parse(line));

    return res.json({ events });
  } catch (err) {
    return res.status(500).json({
      error: "audit_read_failed",
      message: err instanceof Error ? err.message : "Unknown error",
    });
  }
});

app.post("/v4/evaluate", (req, res) => {
  const parsed = EvaluateRequestZ.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
  }

  const commitment = parsed.data.commitment as Commitment;
  const policy = parsed.data.policy as PolicyConfig;

  const decision = evaluate(commitment, policy);

  writeAudit({
    ts: Date.now(),
    commitment,
    decision,
  });

  return res.json({ decision });
});


const port = Number(process.env.PORT || 8787);
Sentry.setupExpressErrorHandler(app);
app.listen(port, () => console.log(`authority-v4 listening on ${port}`));