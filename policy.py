import os
import yaml
from typing import Any, Dict, List


POLICY_PATH = os.getenv("POLICY_PATH", "policy.yaml")


def load_policy() -> Dict[str, Any]:
    if not os.path.exists(POLICY_PATH):
        raise FileNotFoundError(f"Policy file not found: {POLICY_PATH}")

    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Normalize
    data.setdefault("allowed_envs", [])
    data.setdefault("allowed_models", [])
    data.setdefault("allowed_action_types", [])
    data.setdefault("deny_in_prod", False)

    return data


def as_set(value: Any) -> set:
    if value is None:
        return set()
    if isinstance(value, list):
        return set(value)
    return {value}


