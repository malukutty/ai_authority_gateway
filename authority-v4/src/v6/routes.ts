import type { Express, Request, Response } from "express";
import { z } from "zod";
import { getAgentSummaries, getPolicy, getRecentEvents, getSummary, setPolicy } from "./store.js";
import { proxyProviderRequest } from "./proxy.js";

const PolicyPatchZ = z.object({
  agentDailyLimitUsd: z.number().positive().optional(),
  teamDailyLimitUsd: z.number().positive().optional(),
  alertThresholdPct: z.number().min(1).max(100).optional(),
  blockThresholdPct: z.number().min(1).max(100).optional()
});

export function mountV6Routes(app: Express) {
  app.get("/v6/health", (_req: Request, res: Response) => {
    return res.json({ status: "ok", version: "v6" });
  });

  app.get("/v6/metrics/summary", (_req: Request, res: Response) => {
    return res.json({
      summary: getSummary(),
      policy: getPolicy()
    });
  });

  app.get("/v6/metrics/agents", (_req: Request, res: Response) => {
    return res.json({
      agents: getAgentSummaries()
    });
  });

  app.get("/v6/events/recent", (req: Request, res: Response) => {
    const rawLimit = Number(req.query.limit ?? 50);
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(200, Math.floor(rawLimit))) : 50;

    return res.json({
      events: getRecentEvents(limit)
    });
  });

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
} 