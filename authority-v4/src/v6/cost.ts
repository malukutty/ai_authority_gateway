import { getModelPrice } from "./pricing.js";
import type { Provider } from "./types.js";

export function calculateCostUsd(params: {
  provider: Provider;
  model: string;
  inputTokens: number;
  outputTokens: number;
}): number {
  const { provider, model, inputTokens, outputTokens } = params;
  const price = getModelPrice(provider, model);

  const inputCost = (inputTokens / 1000) * price.inputPer1kUsd;
  const outputCost = (outputTokens / 1000) * price.outputPer1kUsd;

  return Number((inputCost + outputCost).toFixed(6));
}

export function extractOpenAIUsage(json: any): { inputTokens: number; outputTokens: number } {
  return {
    inputTokens: Number(json?.usage?.prompt_tokens ?? 0),
    outputTokens: Number(json?.usage?.completion_tokens ?? 0)
  };
}

export function extractAnthropicUsage(json: any): { inputTokens: number; outputTokens: number } {
  return {
    inputTokens: Number(json?.usage?.input_tokens ?? 0),
    outputTokens: Number(json?.usage?.output_tokens ?? 0)
  };
}