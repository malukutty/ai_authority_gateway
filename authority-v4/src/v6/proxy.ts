import type { Request } from "express";
import {
  appendEvent,
  createEventId,
  getAgentSpendToday,
  getPolicy,
  getTeamSpendToday
} from "./store.js";
import { calculateCostUsd, extractAnthropicUsage, extractOpenAIUsage } from "./cost.js";
import { evaluateBudgetPolicy, getEventStatus } from "./policy.js";
import { sendSlackAlert } from "./slack.js";
import type { AttributionHeaders, Provider, UsageEvent } from "./types.js";

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

function getProviderUrl(provider: Provider): string {
  if (provider === "openai") {
    return "https://api.openai.com/v1/chat/completions";
  }
  return "https://api.anthropic.com/v1/messages";
}

function getApiKey(provider: Provider): string {
  const key =
    provider === "openai"
      ? process.env.OPENAI_API_KEY
      : process.env.ANTHROPIC_API_KEY;

  if (!key) {
    throw new Error(`${provider.toUpperCase()} API key is not configured`);
  }

  return key;
}

function getModelFromRequest(provider: Provider, body: any): string {
  if (provider === "openai") return String(body?.model ?? "unknown");
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
  const policy = getPolicy();
  const body = req.body;
  const model = getModelFromRequest(provider, body);

  const currentAgentSpend = getAgentSpendToday(attribution.agentId);
  const currentTeamSpend = getTeamSpendToday(attribution.teamId);

  const projectedAgentSpend = currentAgentSpend + estimatePreflightCostUsd(provider, model);
  const projectedTeamSpend = currentTeamSpend + estimatePreflightCostUsd(provider, model);

  const precheck = evaluateBudgetPolicy({
    policy,
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
      reason: precheck.reason
    };

    appendEvent(blockedEvent);

    await sendSlackAlert({
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      text: `🚫 V6 blocked request. Provider=${provider} agent=${attribution.agentId} team=${attribution.teamId} reason=${precheck.reason}`
    });

    return {
      status: 429,
      body: {
        error: "budget_exceeded",
        message: precheck.reason ?? "Budget limit reached"
      }
    };
  }

  const apiKey = getApiKey(provider);
  const providerResponse = await fetch(getProviderUrl(provider), {
    method: "POST",
    headers: buildProviderHeaders(provider, apiKey),
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
    policy,
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
    reason: postcheck.reason
  };

  appendEvent(event);

  if (postcheck.shouldAlert) {
    await sendSlackAlert({
      webhookUrl: process.env.SLACK_WEBHOOK_URL,
      text: `⚠️ V6 alert. Provider=${provider} agent=${attribution.agentId} team=${attribution.teamId} spend=${costUsd.toFixed(4)} reason=${postcheck.reason}`
    });
  }

  return {
    status: providerResponse.status,
    body: responseJson
  };
} 