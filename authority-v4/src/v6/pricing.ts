import type { Provider } from "./types.js";

export interface ModelPrice {
  inputPer1kUsd: number;
  outputPer1kUsd: number;
}

const OPENAI_PRICING: Record<string, ModelPrice> = {
  "gpt-4o": { inputPer1kUsd: 0.005, outputPer1kUsd: 0.015 },
  "gpt-4o-mini": { inputPer1kUsd: 0.00015, outputPer1kUsd: 0.0006 },
  "gpt-4.1": { inputPer1kUsd: 0.01, outputPer1kUsd: 0.03 },
  "gpt-4.1-mini": { inputPer1kUsd: 0.0004, outputPer1kUsd: 0.0016 }
};

const ANTHROPIC_PRICING: Record<string, ModelPrice> = {
  "claude-3-5-sonnet": { inputPer1kUsd: 0.003, outputPer1kUsd: 0.015 },
  "claude-3-7-sonnet": { inputPer1kUsd: 0.003, outputPer1kUsd: 0.015 },
  "claude-3-opus": { inputPer1kUsd: 0.015, outputPer1kUsd: 0.075 },
  "claude-3-haiku": { inputPer1kUsd: 0.00025, outputPer1kUsd: 0.00125 }
};

export function getModelPrice(provider: Provider, model: string): ModelPrice {
  const normalized = model.trim();
  const table = provider === "openai" ? OPENAI_PRICING : ANTHROPIC_PRICING;
  return table[normalized] ?? { inputPer1kUsd: 0.01, outputPer1kUsd: 0.03 };
}