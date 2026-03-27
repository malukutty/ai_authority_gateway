import type { Request } from "express";
import {
  appendEvent,
  createEventId,
  getAgentSpendToday,
  getTeamSpendToday
} from "./store.js";
import { calculateCostUsd, extractAnthropicUsage, extractOpenAIUsage } from "./cost.js";
import { evaluateBudgetPolicy, getEventStatus } from "./policy.js";
import { sendSlackAlert } from "./slack.js";
import { lookupV6ApiKey } from "./keys.js";
import type { AttributionHeaders, Provider, UsageEvent, V6ApiKeyRecord } from "./types.js";

function requireAttributionHeaders(req: Request): AttributionHeaders {
  const agentId = String(req.header("x-agent-id") ?? "").trim();
  const taskId = String(req.header("x-task-id") ?? "").trim();
  const userId = String(req.header("x-user-id") ?? "").trim();
  const teamId = String(req.header("x-team-id") ?? "").trim();

  if (!agentId || !taskId || !userId || !teamId) {
    throw new Error("Missing required attribution headers: x-agent-id, x-task-id, x-user-id, x-team-id");
  }

  return { agentId, taskId, userId, teamId };
}

function requireV6ApiKey(req: Request): V6ApiKeyRecord {
  const rawKey = String(req.header("x-v6-api-key") ?? "").trim();

  if (!rawKey) {
    throw new Error("Valid V6 API key required");
  }

  const record = lookupV6ApiKey(rawKey);
  if (!record || !record.isActive) {
    throw new Error("Valid V6 API key required");
  }

  return record;
}

function getProviderUrl(provider: Provider): string {
  if (provider === "openai") {
    return "https://api.openai.com/v1/chat/completions";
  }
  return "https://api.anthropic.com/v1/messages";
}

function requireProviderApiKey(req: Request, provider: Provider): string {
  if (provider === "openai") {
    const key = String(req.header("x-openai-api-key") ?? "").trim();
    if (!key) {
      throw new Error("Missing required header: x-openai-api-key");
    }
    return key;
  }

  if (provider === "anthropic") {
    const key = String(req.header("x-anthropic-api-key") ?? "").trim();
    if (!key) {
      throw new Error("Missing required header: x-anthropic-api-key");
    }
    return key;
  }

  throw new Error(`Unsupported provider: ${provider}`);
}

function getModelFromRequest(provider: Provider, body: any): string {
  void provider;
  return String(body?.model ?? "unknown");
}

function buildProviderHeaders(provider: Provider, apiKey: string): HeadersInit {
  if (provider === "openai") {
    return {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    };
  }

  return {
    "Content-Type": "application/json",
    "x-api-key": apiKey,
    "anthropic-version": "2023-06-01"
  };
}

function estimatePreflightCostUsd(provider: Provider, model: string): number {
  void provider;
  void model;
  return 0.05;
}

export async function proxyProviderRequest(params: {
  provider: Provider;
  req: Request;
}): Promise<{
  status: number;
  body: any;
}> {
  const { provider, req } = params;
  const attribution = requireAttributionHeaders(req);
  const keyRecord = requireV6ApiKey(req);
  const providerApiKey = requireProviderApiKey(req, provider);
  const body = req.body;
  const model = getModelFromRequest(provider, body);

  const currentAgentSpend = getAgentSpendToday(attribution.agentId, keyRecord.id);
  const currentTeamSpend = getTeamSpendToday(attribution.teamId, keyRecord.id);

  const projectedAgentSpend = currentAgentSpend + estimatePreflightCostUsd(provider, model);
  const projectedTeamSpend = currentTeamSpend + estimatePreflightCostUsd(provider, model);

  const effectivePolicy = {
    agentDailyLimitUsd: keyRecord.dailySpendLimitUsd,
    teamDailyLimitUsd: keyRecord.teamDailyLimitUsd,
    alertThresholdPct: 80,
    blockThresholdPct: 100
  };

  const precheck = evaluateBudgetPolicy({
    policy: effectivePolicy,
    projectedAgentSpendUsd: projectedAgentSpend,
    projectedTeamSpendUsd: projectedTeamSpend
  });

  if (precheck.shouldBlock) {
    const blockedEvent: UsageEvent = {
      id: createEventId(),
      timestamp: new Date().toISOString(),
      provider,
      model,
      agentId: attribution.agentId,
      taskId: attribution.taskId,
      userId: attribution.userId,
      teamId: attribution.teamId,
      inputTokens: 0,
      outputTokens: 0,
      costUsd: 0,
      status: "blocked",
      reason: precheck.reason,
      apiKeyId: keyRecord.id,
      ownerUserId: keyRecord.userId,
      visibility: keyRecord.visibility
    };

    appendEvent(blockedEvent);

    await sendSlackAlert({
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      text: `🚫 V6 blocked request. provider=${provider} key=${keyRecord.id} agent=${attribution.agentId} team=${attribution.teamId} reason=${precheck.reason}`
    });

    return {
      status: 429,
      body: {
        error: "budget_exceeded",
        message: precheck.reason ?? "Budget limit reached"
      }
    };
  }

  const providerResponse = await fetch(getProviderUrl(provider), {
    method: "POST",
    headers: buildProviderHeaders(provider, providerApiKey),
    body: JSON.stringify(body)
  });

  const responseJson = await providerResponse.json();

  const usage =
    provider === "openai"
      ? extractOpenAIUsage(responseJson)
      : extractAnthropicUsage(responseJson);

  const costUsd = calculateCostUsd({
    provider,
    model,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens
  });

  const finalAgentSpend = currentAgentSpend + costUsd;
  const finalTeamSpend = currentTeamSpend + costUsd;

  const postcheck = evaluateBudgetPolicy({
    policy: effectivePolicy,
    projectedAgentSpendUsd: finalAgentSpend,
    projectedTeamSpendUsd: finalTeamSpend
  });

  const status = getEventStatus({
    blocked: false,
    alerted: postcheck.shouldAlert
  });

  const event: UsageEvent = {
    id: createEventId(),
    timestamp: new Date().toISOString(),
    provider,
    model,
    agentId: attribution.agentId,
    taskId: attribution.taskId,
    userId: attribution.userId,
    teamId: attribution.teamId,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    costUsd,
    status,
    reason: postcheck.reason,
    apiKeyId: keyRecord.id,
    ownerUserId: keyRecord.userId,
    visibility: keyRecord.visibility
  };

  appendEvent(event);

  if (postcheck.shouldAlert) {
    await sendSlackAlert({
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      text: `⚠️ V6 alert. provider=${provider} key=${keyRecord.id} agent=${attribution.agentId} team=${attribution.teamId} spend=${costUsd.toFixed(4)} reason=${postcheck.reason}`
    });
  }

  return {
    status: providerResponse.status,
    body: responseJson
  };
} 