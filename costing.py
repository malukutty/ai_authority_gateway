from typing import Dict


def estimate_cost_usd(model: str, usage: Dict[str, int], pricing: Dict) -> float:
    """
    pricing:
      { model: { input_per_1m: float, output_per_1m: float } }
    """
    model_price = pricing.get(model)
    if not model_price:
        # No pricing info: treat as unknown/high risk
        return float("inf")

    in_rate = float(model_price.get("input_per_1m", 0.0))
    out_rate = float(model_price.get("output_per_1m", 0.0))

    prompt_tokens = int(usage.get("prompt_tokens", 0))
    completion_tokens = int(usage.get("completion_tokens", 0))

    return (prompt_tokens / 1_000_000.0) * in_rate + (completion_tokens / 1_000_000.0) * out_rate
