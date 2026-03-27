import type { Express, Request, Response } from "express";
import { z } from "zod";
import { getAgentSummaries, getPolicy, getRecentEvents, getSummary, setPolicy } from "./store.js";
import { proxyProviderRequest } from "./proxy.js";
import { maskAgentId, maskTaskId, maskTeamId, maskUserId } from "./mask.js";
import { listV6ApiKeysByUser } from "./keys.js";

const PolicyPatchZ = z.object({
  agentDailyLimitUsd: z.number().positive().optional(),
  teamDailyLimitUsd: z.number().positive().optional(),
  alertThresholdPct: z.number().min(1).max(100).optional(),
  blockThresholdPct: z.number().min(1).max(100).optional()
});

function toMaskedEvent(event: any) {
  return {
    ...event,
    agentId: maskAgentId(event.agentId),
    taskId: maskTaskId(event.taskId),
    userId: maskUserId(event.userId),
    teamId: maskTeamId(event.teamId)
  };
}

function toMaskedAgent(agent: any) {
  return {
    ...agent,
    agentId: maskAgentId(agent.agentId),
    teamId: maskTeamId(agent.teamId),
    userId: maskUserId(agent.userId)
  };
}

export function mountV6Routes(app: Express) {
  app.get("/v6/health", (_req: Request, res: Response) => {
    return res.json({ status: "ok", version: "v6" });
  });

  // Public dashboard data
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
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;

    const events = getRecentEvents(limit, { visibility: "public" }).map(toMaskedEvent);
    return res.json({ events });
  });

  // Global fallback policy remains for now
  app.get("/v6/policy", (_req: Request, res: Response) => {
    return res.json({
      policy: getPolicy()
    });
  });

  app.post("/v6/policy", (req: Request, res: Response) => {
    const parsed = PolicyPatchZ.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "invalid_request", issues: parsed.error.issues });
    }

    const policy = setPolicy(parsed.data);
    return res.json({ policy });
  });

  app.post("/v6/proxy/openai", async (req: Request, res: Response) => {
    try {
      const result = await proxyProviderRequest({ provider: "openai", req });
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
      const result = await proxyProviderRequest({ provider: "anthropic", req });
      return res.status(result.status).json(result.body);
    } catch (error) {
      return res.status(400).json({
        error: "proxy_failed",
        message: error instanceof Error ? error.message : "Unknown proxy error"
      });
    }
  });

  // Optional private endpoints for later frontend wiring
  app.get("/v6/private/metrics/summary/:userId", (req: Request, res: Response) => {
    return res.json({
      summary: getSummary({ visibility: "private", ownerUserId: req.params.userId }),
      policy: getPolicy()
    });
  });

  app.get("/v6/private/metrics/agents/:userId", (req: Request, res: Response) => {
    return res.json({
      agents: getAgentSummaries({ visibility: "private", ownerUserId: req.params.userId })
    });
  });

  app.get("/v6/keys/:userId", (req: Request, res: Response) => {
  return res.json({
    keys: listV6ApiKeysByUser(req.params.userId)
  });
});

  app.get("/v6/private/events/recent/:userId", (req: Request, res: Response) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;

    return res.json({
      events: getRecentEvents(limit, { visibility: "private", ownerUserId: req.params.userId })
    });
  });
} 
