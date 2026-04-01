import type { Express, Request, Response } from "express";
import { z } from "zod";
import {
  getAgentSummaries,
  getPolicy,
  getRecentEvents,
  getSummary,
  setPolicy
} from "./store.js";
import { proxyProviderRequest } from "./proxy.js";
import {
  createV6ApiKey,
  listV6ApiKeysByUser
} from "./keys.js";
import {
  maskAgentId,
  maskTaskId,
  maskTeamId,
  maskUserId
} from "./mask.js";

import { seedPublicBackfill, seedPublicTick } from "./seed.js";

const PolicyPatchZ = z.object({
  agentDailyLimitUsd: z.number().positive().optional(),
  teamDailyLimitUsd: z.number().positive().optional(),
  alertThresholdPct: z.number().min(1).max(100).optional(),
  blockThresholdPct: z.number().min(1).max(100).optional()
});

const CreateKeyZ = z.object({
  userId: z.string().min(1),
  visibility: z.enum(["public", "private"]).default("private"),
  dailySpendLimitUsd: z.number().positive().optional(),
  teamDailyLimitUsd: z.number().positive().optional(),
  requestsPerMinute: z.number().int().positive().optional()
});

function toMaskedEvent(event: any) {
  return {
    id: event.id,
    timestamp: event.timestamp,
    provider: event.provider,
    model: event.model,
    agentId: maskAgentId(event.agentId),
    taskId: maskTaskId(event.taskId),
    userId: maskUserId(event.userId),
    teamId: maskTeamId(event.teamId),
    inputTokens: event.inputTokens,
    outputTokens: event.outputTokens,
    costUsd: event.costUsd,
    status: event.status,
    reason: event.reason,
    visibility: event.visibility
  };
}

function toMaskedAgent(agent: any) {
  return {
    agentId: maskAgentId(agent.agentId),
    teamId: maskTeamId(agent.teamId),
    userId: maskUserId(agent.userId),
    requestCount: agent.requestCount,
    spendToday: agent.spendToday,
    avgCostPerRequest: agent.avgCostPerRequest,
    lastSeen: agent.lastSeen,
    status: agent.status
  };
}

export function mountV6Routes(app: Express) {
  app.get("/v6/health", (_req: Request, res: Response) => {
    return res.json({ status: "ok", version: "v6" });
  });

app.post("/v6/dev/seed-public", (req: Request, res: Response) => {
    const secret = String(req.header("x-seed-secret") ?? "").trim();

    if (!secret || secret !== process.env.SEED_SECRET) {
      return res.status(403).json({ error: "unauthorized" });
    }

    const action = String(req.query.action ?? "tick").trim();

    if (action === "backfill") {
      const inserted = seedPublicBackfill(180);
      return res.json({ ok: true, action, inserted });
    }

    const inserted = seedPublicTick(1, 3);
    return res.json({ ok: true, action: "tick", inserted });
  });


  // Public dashboard endpoints
  app.get("/v6/metrics/summary", (_req: Request, res: Response) => {
    return res.json({
      summary: getSummary({ visibility: "public" }),
      policy: getPolicy()
    });
  });

  app.get("/v6/metrics/agents", (_req: Request, res: Response) => {
    const agents = getAgentSummaries({ visibility: "public" }).map(toMaskedAgent);
    return res.json({ agents });
  });

  app.get("/v6/events/recent", (req: Request, res: Response) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit)
      ? Math.max(1, Math.min(200, Math.floor(rawLimit)))
      : 50;

    const events = getRecentEvents(limit, { visibility: "public" }).map(toMaskedEvent);
    return res.json({ events });
  });

  // Global fallback policy
  app.get("/v6/policy", (_req: Request, res: Response) => {
    return res.json({
      policy: getPolicy()
    });
  });

  app.post("/v6/policy", (req: Request, res: Response) => {
    const parsed = PolicyPatchZ.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_request",
        issues: parsed.error.issues
      });
    }

    const policy = setPolicy(parsed.data);
    return res.json({ policy });
  });

  // V6 key creation
  app.post("/v6/keys/create", (req: Request, res: Response) => {
    const parsed = CreateKeyZ.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        error: "invalid_request",
        issues: parsed.error.issues
      });
    }

    const { token, record } = createV6ApiKey({
      userId: parsed.data.userId,
      visibility: parsed.data.visibility,
      dailySpendLimitUsd: parsed.data.dailySpendLimitUsd,
      teamDailyLimitUsd: parsed.data.teamDailyLimitUsd,
      requestsPerMinute: parsed.data.requestsPerMinute
    });

    return res.json({
      token,
      record
    });
  });

  // List V6 keys for a user
  app.get("/v6/keys", (req: Request, res: Response) => {
    const userId = String(req.header("x-user-id") ?? "").trim();

    if (!userId) {
      return res.status(400).json({
        error: "missing_user_id"
      });
    }

    return res.json({
      keys: listV6ApiKeysByUser(userId)
    });
  });

  // Proxy endpoints
  app.post("/v6/proxy/openai", async (req: Request, res: Response) => {
    try {
      const result = await proxyProviderRequest({
        provider: "openai",
        req
      });
      return res.status(result.status).json(result.body);
    } catch (error) {
      return res.status(400).json({
        error: "proxy_failed",
        message: error instanceof Error ? error.message : "Unknown proxy error"
      });
    }
  });

  app.post("/v6/proxy/anthropic", async (req: Request, res: Response) => {
    try {
      const result = await proxyProviderRequest({
        provider: "anthropic",
        req
      });
      return res.status(result.status).json(result.body);
    } catch (error) {
      return res.status(400).json({
        error: "proxy_failed",
        message: error instanceof Error ? error.message : "Unknown proxy error"
      });
    }
  });

  // Private endpoints for logged-in/private views
  app.get("/v6/private/metrics/summary/:userId", (req: Request, res: Response) => {
    return res.json({
      summary: getSummary({
        visibility: "private",
        ownerUserId: req.params.userId
      }),
      policy: getPolicy()
    });
  });

  app.get("/v6/private/metrics/agents/:userId", (req: Request, res: Response) => {
    return res.json({
      agents: getAgentSummaries({
        visibility: "private",
        ownerUserId: req.params.userId
      })
    });
  });

  app.get("/v6/private/events/recent/:userId", (req: Request, res: Response) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit)
      ? Math.max(1, Math.min(200, Math.floor(rawLimit)))
      : 50;

    return res.json({
      events: getRecentEvents(limit, {
        visibility: "private",
        ownerUserId: req.params.userId
      })
    });
  });
} 